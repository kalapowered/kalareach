//! What an invocation for a caller bounded by a grant can read.
//!
//! On Linux such an invocation runs inside one Landlock ruleset with no rule on the whole
//! filesystem. On macOS it runs inside a sandbox profile that denies by default and names what it
//! may read. On both it reads the directories the operation owns, the ones it is lent, Git's own
//! program and helper directory, the device nodes and the support set named for this host's Git,
//! and nothing else the account can read. Each refusal here sits beside its control: the same
//! operation on the same objects with exactly one restriction lifted, which reads what the refusal
//! did not. Where the refusal is the system's, it is shown in the child's own words, as a refusal
//! to open the object, rather than as an exit code.
//!
//! Elsewhere no platform confines what Git reads, and such an invocation is refused with the
//! reason.

mod support;

use kr_project::git::ReadAdmission;
use support::Fixture;

/// An admission that asks nothing, for an operation performed for a caller bounded by a grant.
fn bounded() -> Option<ReadAdmission> {
    Some(ReadAdmission::new(|| Ok(())).bounded())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn a_platform_that_does_not_confine_reads_refuses_a_bounded_caller_with_its_reason() {
    let fixture = Fixture::create();
    let path = support::ordinary_repository(fixture.work(), "refused");
    let arguments = [
        std::ffi::OsStr::new("status"),
        std::ffi::OsStr::new("--porcelain"),
    ];
    let refusal = fixture
        .service()
        .profile()
        .run(&kr_project::git::GitRequest::read(&path, &arguments).admitted(bounded()))
        .expect_err("a caller bounded by a grant is refused where reads are not confined");
    // A platform that runs no Git at all says so before it looks for Git, so a bounded caller is
    // told that rather than that its reads are not confined.
    let said = if cfg!(windows) {
        "cannot bound which ports"
    } else {
        "this platform does not confine what Git reads"
    };
    assert!(
        refusal.to_string().contains(said),
        "the refusal says why: {refusal}"
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn a_platform_that_does_not_confine_reads_does_not_qualify_and_starts_no_git_to_say_so() {
    let fixture = Fixture::create();
    let proved = fixture.service().qualify();
    assert!(!proved.qualifies());
    assert_eq!(
        proved.refusal(),
        Some(kr_project::service::Refusal::Platform)
    );
    assert_eq!(
        proved.narrowing(),
        &kr_project::service::Narrowing::default(),
        "nothing about mounts is read where nothing is confined"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod confined {
    use std::ffi::{OsStr, OsString};
    use std::io::Read as _;
    use std::path::{Path, PathBuf};

    use kr_project::boundary::{Confinement, Invocation, OpenedDirectory, Reach, Reads};
    use kr_project::git::{ConfigurationAudit, GitRequest, RemoteAccess};
    use kr_project::identity::OpenedRepository;

    use super::{Fixture, bounded, support};

    /// What the child's own error says when the system refuses it a file or a program: the
    /// kernel's words on Linux, and the sandbox's on macOS.
    const REFUSED: &str = if cfg!(target_os = "macos") {
        "Operation not permitted"
    } else {
        "Permission denied"
    };

    /// What one enclosed child did, in its own words, and the environment it was given.
    struct Outcome {
        status: Option<i32>,
        stdout: String,
        stderr: String,
        /// Read by the case that compares what Git printed with what it was given.
        #[cfg(target_os = "linux")]
        environment: Vec<(OsString, OsString)>,
    }

    /// One child to start inside the boundary.
    struct Enclosed<'a> {
        program: &'a Path,
        arguments: Vec<OsString>,
        helpers: Vec<PathBuf>,
        readable: Vec<PathBuf>,
        reads: Reads,
        /// The directory the child may execute programs from, when it is not Git's own.
        exec_path: Option<PathBuf>,
    }

    /// Starts one child inside the boundary as the profile starts Git, and keeps the child's own
    /// standard error rather than reducing it to its class: these tests have to see what the
    /// kernel refused.
    ///
    /// The confinement is built from the profile's own parts, with the profile's own directories
    /// readable as every invocation's are, and the child's temporary directory made for it.
    fn run_enclosed(fixture: &Fixture, working: &Path, enclosed: Enclosed<'_>) -> Outcome {
        let profile = fixture.service().profile();
        let git = profile.git().expect("Git is installed");
        let environment_id = fixture.environment_id();
        let temporary = tempfile::TempDir::new().expect("a temporary directory for the child");
        let confinement = Confinement {
            program: enclosed.program.to_owned(),
            exec_path: enclosed
                .exec_path
                .unwrap_or_else(|| git.exec_path().to_owned()),
            helpers: enclosed.helpers,
            working: OpenedDirectory::open(environment_id, working, None)
                .expect("the working directory opens"),
            reserved: Vec::new(),
            temporary: OpenedDirectory::open(environment_id, temporary.path(), None)
                .expect("the temporary directory opens"),
            readable: [
                git.program(),
                profile.empty_config(),
                profile.hooks_directory(),
                profile.home_directory(),
            ]
            .into_iter()
            .map(Path::to_owned)
            .chain(enclosed.readable)
            .collect(),
            reach: Reach::Nothing,
            reads: enclosed.reads,
        };
        let nothing: [&OsStr; 0] = [];
        let environment = profile
            .environment(&GitRequest::read(working, &nothing), temporary.path())
            .expect("Git is installed");
        let mut child = kr_project::boundary::start(
            &Invocation {
                program: enclosed.program,
                arguments: &enclosed.arguments,
                environment: &environment,
                described: "a child these tests enclose",
            },
            &confinement,
        )
        .expect("the child starts");
        let mut stdout = String::new();
        child
            .stdout()
            .expect("its standard output")
            .read_to_string(&mut stdout)
            .expect("its standard output reads");
        let mut stderr = String::new();
        child
            .stderr()
            .expect("its standard error")
            .read_to_string(&mut stderr)
            .expect("its standard error reads");
        let status = loop {
            if let Some(status) = child.try_wait().expect("the child can be waited on") {
                break status;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        Outcome {
            status: status.code(),
            stdout,
            stderr,
            #[cfg(target_os = "linux")]
            environment,
        }
    }

    /// Returns the argument vector the profile gives Git for one read in a directory.
    fn git_arguments(fixture: &Fixture, directory: &Path, arguments: &[&OsStr]) -> Vec<OsString> {
        fixture
            .service()
            .profile()
            .argument_vector(&GitRequest::read(directory, arguments))
    }

    /// Returns the read confinement a caller bounded by a grant runs with on this host.
    fn bounded_reads(fixture: &Fixture) -> Reads {
        Reads::Bounded(
            fixture
                .service()
                .profile()
                .support_set()
                .expect("this host names the support set of its Git"),
        )
    }

    /// Reads one file as configuration through Git, which prints each entry it read.
    fn read_as_configuration(
        fixture: &Fixture,
        working: &Path,
        file: &Path,
        readable: Vec<PathBuf>,
        reads: Reads,
    ) -> Outcome {
        let named = format!("--file={}", file.display());
        let program = fixture
            .service()
            .profile()
            .git()
            .expect("Git is installed")
            .executable()
            .to_owned();
        run_enclosed(
            fixture,
            working,
            Enclosed {
                program: &program,
                arguments: git_arguments(
                    fixture,
                    working,
                    &[
                        OsStr::new("config"),
                        OsStr::new(&named),
                        OsStr::new("--list"),
                    ],
                ),
                helpers: Vec::new(),
                readable,
                reads,
                exec_path: None,
            },
        )
    }

    /// Asserts that one read was the kernel refusing to open the file, and that nothing of it was
    /// read.
    fn assert_refused(outcome: &Outcome, secret: &str, what: &str) {
        assert_ne!(outcome.status, Some(0), "{what}: Git reports the failure");
        assert!(
            outcome.stderr.contains(REFUSED),
            "{what}: the kernel refused to open it, and Git said {}",
            outcome.stderr
        );
        assert!(
            !outcome.stdout.contains(secret) && !outcome.stderr.contains(secret),
            "{what}: nothing of it was read"
        );
    }

    /// A host proves it runs Git for a caller bounded by a grant by running one invocation under
    /// the rules such a caller runs under. The control is the same proof where that invocation
    /// does not run: the directory it was started in is replaced between its opening and its
    /// start, which the boundary refuses, and the host is then one that did not qualify.
    #[test]
    fn a_host_proves_the_boundary_by_running_it_and_does_not_qualify_where_it_does_not_run() {
        use kr_project::service::Refusal;

        let mut fixture = Fixture::create();
        let proved = fixture.service().qualify();
        assert!(
            proved.qualifies(),
            "this host proves the boundary: {:?}: {}",
            proved.refusal(),
            proved.detail()
        );
        assert!(proved.detail().is_empty());
        #[cfg(target_os = "linux")]
        {
            let reading = proved.narrowing();
            assert!(
                reading.user_namespaces.is_some() && reading.automounts.is_some(),
                "the narrowing facts are read on Linux: {reading:?}"
            );
        }

        let home = fixture.service().profile().home_directory().to_owned();
        let moved = home.with_file_name("home-moved-aside");
        fixture.interpose(kr_project::git::Interposition::new(std::sync::Arc::new(
            move |described: &str, _working: &Path, _temporary: &Path| {
                if described.starts_with("git config") && !moved.exists() {
                    std::fs::rename(&home, &moved).expect("the home directory moves aside");
                    std::fs::create_dir(&home).expect("another directory takes its name");
                }
            },
        )));
        let refused = fixture.service().qualify();
        assert!(!refused.qualifies());
        assert_eq!(refused.refusal(), Some(Refusal::Invocation));
        assert!(
            !refused.detail().is_empty(),
            "the daemon's own log is told what stopped it"
        );
    }

    /// A kernel without the interface the rules need does not qualify, and the doctor is told that
    /// cause and not that the host cannot name its Git's libraries. The kernel is not changed: the
    /// answer to the boundary's own probe is, on this thread only.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_without_the_interface_does_not_qualify_and_is_not_taken_for_a_missing_library() {
        use kr_project::service::Refusal;

        let fixture = Fixture::create();

        let refused =
            kr_project::boundary::with_kernel_interface(2, || fixture.service().qualify());

        assert!(!refused.qualifies());
        assert_eq!(refused.refusal(), Some(Refusal::Invocation));
        assert!(
            refused.detail().contains("version 2") && refused.detail().contains("version 3"),
            "the daemon's own log is told what the kernel has and what the rules need: {}",
            refused.detail()
        );
    }

    /// A platform that runs no Git does not qualify, and the doctor is told that cause and not
    /// that the host cannot name its Git's libraries. The machine is not changed: the answer to
    /// whether the platform runs Git is, on this thread only.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_platform_that_runs_no_git_does_not_qualify_and_is_not_taken_for_a_missing_library() {
        use kr_project::service::Refusal;

        let fixture = Fixture::create();

        let refused = kr_project::boundary::with_no_git("a reason of the platform", || {
            fixture.service().qualify()
        });

        assert!(!refused.qualifies());
        assert_eq!(refused.refusal(), Some(Refusal::Invocation));
        assert!(
            refused.detail().contains("a reason of the platform"),
            "the daemon's own log is told the platform's reason: {}",
            refused.detail()
        );
    }

    #[test]
    fn a_bounded_caller_can_status_clone_check_out_and_add_a_worktree() {
        let fixture = Fixture::create();
        let profile = fixture.service().profile();
        let path = support::ordinary_repository(fixture.work(), "source");
        let repository = OpenedRepository::open(profile, fixture.environment_id(), &path)
            .expect("the repository opens");
        let (head, _) = repository.head(profile).expect("the head reads");
        let revision = head.expect("a commit");

        // A status, under the complete production profile, with reads bounded.
        let status: [&OsStr; 3] = [
            OsStr::new("status"),
            OsStr::new("--porcelain=v2"),
            OsStr::new("--ignore-submodules=all"),
        ];
        let listed = profile
            .run(&repository.read(&status).admitted(bounded()))
            .expect("the status starts");
        assert!(listed.success, "the status runs: {}", listed.stderr);

        // A clone from the location into a staging directory, as a materialisation makes one.
        let staging = fixture.work().join("staging");
        std::fs::create_dir(&staging).expect("a staging directory");
        let clone: [&OsStr; 7] = [
            OsStr::new("clone"),
            OsStr::new("--template="),
            OsStr::new("--no-hardlinks"),
            OsStr::new("--no-checkout"),
            OsStr::new("--"),
            path.as_os_str(),
            OsStr::new("tree"),
        ];
        let cloned = profile
            .run(
                &GitRequest::write(&staging, &clone)
                    .with_ceiling(&staging)
                    .reading(&[path.as_path()])
                    .with_transport(RemoteAccess::local())
                    .admitted(bounded()),
            )
            .expect("the clone starts");
        assert!(cloned.success, "the clone runs: {}", cloned.stderr);

        // Its checkout, a separate invocation.
        let tree = staging.join("tree");
        let checkout: [&OsStr; 3] = [
            OsStr::new("checkout"),
            OsStr::new("--detach"),
            OsStr::new(&revision),
        ];
        let checked = profile
            .run(
                &GitRequest::write(&tree, &checkout)
                    .with_ceiling(&staging)
                    .admitted(bounded()),
            )
            .expect("the checkout starts");
        assert!(checked.success, "the checkout runs: {}", checked.stderr);
        assert_eq!(
            std::fs::read_to_string(tree.join("README.md")).expect("the checked-out file"),
            "a repository\n",
            "and the tree is the repository's"
        );

        // A linked worktree into a directory reserved for it.
        let reserved = fixture.work().join("worktree");
        std::fs::create_dir(&reserved).expect("a reserved directory");
        let identity = kr_project::boundary::identity_of(fixture.environment_id(), &reserved)
            .expect("the reserved directory's identity");
        let worktree: [&OsStr; 5] = [
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("--detach"),
            reserved.as_os_str(),
            OsStr::new(&revision),
        ];
        let added = profile
            .run(
                &repository
                    .write(&worktree)
                    .writing(&[(reserved.as_path(), identity)])
                    .admitted(bounded()),
            )
            .expect("the worktree starts");
        assert!(added.success, "the worktree is added: {}", added.stderr);
        assert!(
            reserved.join("src").join("lib.rs").is_file(),
            "and it holds the repository's tree"
        );
    }

    #[test]
    fn a_file_outside_every_grant_is_refused_and_the_owners_reads_reach_it() {
        let fixture = Fixture::create();
        let location = fixture.work().join("location");
        std::fs::create_dir(&location).expect("a location");
        let outside = tempfile::TempDir::new().expect("a directory outside the location");
        let secret = outside.path().join("secret.config");
        std::fs::write(&secret, "[secret]\n\tvalue = outside-every-grant\n")
            .expect("a file outside every grant");

        let confined = read_as_configuration(
            &fixture,
            &location,
            &secret,
            Vec::new(),
            bounded_reads(&fixture),
        );
        assert_refused(&confined, "outside-every-grant", "bounded reads");
        // The control is the owner's ruleset, which is the same ruleset with the one rule on the
        // whole filesystem added.
        let owner =
            read_as_configuration(&fixture, &location, &secret, Vec::new(), Reads::Everywhere);
        assert!(
            owner.stdout.contains("secret.value=outside-every-grant"),
            "the owner's reads reach it: {} {}",
            owner.stdout,
            owner.stderr
        );
    }

    #[test]
    fn a_link_in_the_location_to_an_outside_file_is_refused_at_the_file_it_names() {
        let fixture = Fixture::create();
        let location = fixture.work().join("location");
        std::fs::create_dir(&location).expect("a location");
        let outside = tempfile::TempDir::new().expect("a directory outside the location");
        let secret = outside.path().join("secret.config");
        std::fs::write(&secret, "[secret]\n\tvalue = behind-a-link\n").expect("the outside file");
        let link = location.join("link.config");
        std::os::unix::fs::symlink(&secret, &link).expect("a link inside the location");

        let confined = read_as_configuration(
            &fixture,
            &location,
            &link,
            Vec::new(),
            bounded_reads(&fixture),
        );
        assert_refused(&confined, "behind-a-link", "a link to an outside file");
        // The control: the same link to the same file, and one read grant added on the directory
        // the file is in. The link is not moved and its target is not changed.
        let granted = read_as_configuration(
            &fixture,
            &location,
            &link,
            vec![outside.path().to_owned()],
            bounded_reads(&fixture),
        );
        assert!(
            granted.stdout.contains("secret.value=behind-a-link"),
            "with its directory granted the file is read: {} {}",
            granted.stdout,
            granted.stderr
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_secret_in_each_broad_system_directory_is_refused() {
        let fixture = Fixture::create();
        let location = fixture.work().join("location");
        std::fs::create_dir(&location).expect("a location");

        // Shared memory, where any program of the account can leave something.
        let planted = PathBuf::from(format!(
            "/dev/shm/kr-reads-{}.config",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&planted, "[secret]\n\tvalue = in-shared-memory\n")
            .expect("a file in shared memory");
        let confined = read_as_configuration(
            &fixture,
            &location,
            &planted,
            Vec::new(),
            bounded_reads(&fixture),
        );
        let granted = read_as_configuration(
            &fixture,
            &location,
            &planted,
            vec![PathBuf::from("/dev/shm")],
            bounded_reads(&fixture),
        );
        std::fs::remove_file(&planted).expect("the planted file goes");
        assert_refused(&confined, "in-shared-memory", "shared memory");
        assert!(
            granted.stdout.contains("secret.value=in-shared-memory"),
            "with shared memory granted the file is read: {} {}",
            granted.stdout,
            granted.stderr
        );

        // The process's own environment, under the kernel's process tree. Git reads it as
        // configuration and prints an entry of it, with the key in lower case. The control is the
        // owner's ruleset: a read grant on that tree is one the mount check refuses on a host with
        // a filesystem mounted beneath it, which is most hosts.
        let environ = Path::new("/proc/self/environ");
        let entries = |outcome: &Outcome| -> Vec<String> {
            outcome
                .environment
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        key.to_string_lossy().to_ascii_lowercase(),
                        value.to_string_lossy()
                    )
                })
                .collect()
        };
        let confined = read_as_configuration(
            &fixture,
            &location,
            environ,
            Vec::new(),
            bounded_reads(&fixture),
        );
        assert_refused(&confined, "the child's environment", "the process tree");
        for entry in entries(&confined) {
            assert!(
                !confined.stdout.contains(&entry) && !confined.stderr.contains(&entry),
                "nothing of the environment was read, and {entry} was"
            );
        }
        let owner =
            read_as_configuration(&fixture, &location, environ, Vec::new(), Reads::Everywhere);
        let printed: Vec<&str> = owner.stdout.lines().collect();
        assert!(
            owner.status == Some(0)
                && !printed.is_empty()
                && printed
                    .iter()
                    .all(|line| entries(&owner).iter().any(|entry| entry == line)),
            "the owner's reads reach it, and Git printed entries of the environment the child was \
             given: {} {}",
            owner.stdout,
            owner.stderr
        );

        // The system's own name, which Git reads as a key with no value and prints as it is.
        let hostname = Path::new("/etc/hostname");
        let named = std::fs::read_to_string(hostname)
            .map(|name| name.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if named.is_empty() {
            println!("not exercised for /etc: this host keeps no name in /etc/hostname");
        } else {
            let confined = read_as_configuration(
                &fixture,
                &location,
                hostname,
                Vec::new(),
                bounded_reads(&fixture),
            );
            assert_refused(&confined, &named, "the system's configuration directory");
            let granted = read_as_configuration(
                &fixture,
                &location,
                hostname,
                vec![PathBuf::from("/etc")],
                bounded_reads(&fixture),
            );
            assert!(
                granted.stdout.to_ascii_lowercase().contains(&named),
                "with that directory granted the file is read: {} {}",
                granted.stdout,
                granted.stderr
            );
        }
    }

    #[test]
    fn a_program_planted_in_the_writable_location_is_not_executed() {
        let fixture = Fixture::create();
        let location = fixture.work().join("location");
        std::fs::create_dir(&location).expect("a location");
        let planted = location.join("planted-program");
        // On Apple platforms the system's `sh` is a stand-in that looks up the shell it stands for
        // before it runs anything, so the case uses the shell itself.
        let (shell, interpreter) = if cfg!(target_os = "macos") {
            (Path::new("/bin/bash"), "#!/bin/bash")
        } else {
            (Path::new("/bin/sh"), "#!/bin/sh")
        };
        // Placed rather than written here, so no child another test starts can hold it open for
        // writing and have the kernel refuse it as busy, which is not the refusal under test.
        kr_ipc::testing::place_script(
            &planted,
            format!("{interpreter}\necho planted-program-ran\n"),
        );
        let run = |helpers: Vec<PathBuf>| {
            run_enclosed(
                &fixture,
                &location,
                Enclosed {
                    program: shell,
                    arguments: vec![OsString::from("-c"), OsString::from("./planted-program")],
                    helpers,
                    readable: Vec::new(),
                    reads: bounded_reads(&fixture),
                    exec_path: None,
                },
            )
        };
        let refused = run(Vec::new());
        assert!(
            !refused.stdout.contains("planted-program-ran"),
            "the planted program did not run"
        );
        assert!(
            refused.stderr.contains(REFUSED),
            "the kernel refused to execute it: {}",
            refused.stderr
        );
        // The control: the same program in the same location, and one execute grant added on that
        // file.
        let granted = run(vec![planted.clone()]);
        assert!(
            granted.stdout.contains("planted-program-ran"),
            "with the file granted execution it runs: {} {}",
            granted.stdout,
            granted.stderr
        );
    }

    #[test]
    fn an_object_behind_an_alternate_outside_the_location_is_not_read() {
        let fixture = Fixture::create();
        let profile = fixture.service().profile();
        // A repository outside the location holding an object nothing inside has.
        let outside = tempfile::TempDir::new().expect("a directory outside the location");
        let other = support::ordinary_repository(outside.path(), "other");
        support::write(&other, "secret.txt", "an-object-behind-an-alternate\n");
        let blob = support::git_raw(&other, ["hash-object", "-w", "secret.txt"])
            .trim()
            .to_owned();
        // A repository in the location whose object store names the other one's as an alternate.
        let path = support::ordinary_repository(fixture.work(), "borrowing");
        let objects = other.join(".git").join("objects");
        support::write(
            &path,
            ".git/objects/info/alternates",
            &format!("{}\n", objects.display()),
        );
        let repository = OpenedRepository::open(profile, fixture.environment_id(), &path)
            .expect("the repository opens");
        let arguments: [&OsStr; 3] = [OsStr::new("cat-file"), OsStr::new("-p"), OsStr::new(&blob)];
        let confined = profile
            .run(&repository.read(&arguments).admitted(bounded()))
            .expect("the read starts");
        assert!(
            !confined.success && !String::from_utf8_lossy(&confined.stdout).contains("an-object"),
            "the object behind the alternate is not read"
        );
        // The control: the same repository, the same alternate, and one read grant added on the
        // outside object store.
        let granted = profile
            .run(
                &repository
                    .read(&arguments)
                    .reading(&[objects.as_path()])
                    .admitted(bounded()),
            )
            .expect("the read starts");
        assert!(
            granted.success
                && String::from_utf8_lossy(&granted.stdout)
                    .contains("an-object-behind-an-alternate"),
            "with the object store granted the object is read: {}",
            granted.stderr
        );
    }

    #[test]
    fn the_configuration_audit_runs_inside_the_boundary_and_cannot_read_an_outside_include() {
        let fixture = Fixture::create();
        let profile = fixture.service().profile();
        let outside = tempfile::TempDir::new().expect("a directory outside the location");
        let included = outside.path().join("included.config");
        std::fs::write(&included, "[secret]\n\tvalue = included-from-outside\n")
            .expect("an include outside the location");
        let path = support::ordinary_repository(fixture.work(), "including");
        support::git_raw(
            &path,
            [
                OsStr::new("config"),
                OsStr::new("--local"),
                OsStr::new("include.path"),
                included.as_os_str(),
            ],
        );
        // The audit, as a repository reached for a caller bounded by a grant takes it: the
        // include is not read when the listing is made, so the audit is refused rather than
        // produced from it.
        let refusal = ConfigurationAudit::take(profile, &path, None, bounded().as_ref(), None)
            .expect_err("an audit that cannot read an include is not an audit of it");
        assert!(
            !refusal.to_string().contains("included-from-outside"),
            "and nothing of the include is repeated: {refusal}"
        );
        // The listing the audit is taken from, under the same boundary, does not hold it.
        let arguments: [&OsStr; 3] = [
            OsStr::new("config"),
            OsStr::new("--list"),
            OsStr::new("--null"),
        ];
        let confined = profile
            .run(&GitRequest::read(&path, &arguments).admitted(bounded()))
            .expect("the listing starts");
        assert!(
            !String::from_utf8_lossy(&confined.stdout).contains("included-from-outside"),
            "the listing holds nothing of the include"
        );
        // The control: the same repository, the same include, and one read grant added on the
        // include's directory.
        let granted = profile
            .run(
                &GitRequest::read(&path, &arguments)
                    .reading(&[outside.path()])
                    .admitted(bounded()),
            )
            .expect("the listing starts");
        assert!(
            granted.success
                && String::from_utf8_lossy(&granted.stdout).contains("included-from-outside"),
            "with its directory granted the include is read: {}",
            granted.stderr
        );
        // And the owner's audit of the same repository is taken as it always was.
        ConfigurationAudit::take(profile, &path, None, None, None)
            .expect("the owner's audit reads the include");
    }

    /// A grant with a filesystem mounted beneath it is refused with the reason, on this host's own
    /// mount table.
    ///
    /// The host's device tree always has filesystems mounted beneath it, so it stands in for a
    /// granted directory with one. Its control is not here, because no test can take the host's
    /// own mounts away: the comparison is tested with and without the one mount over the same
    /// directories in `boundary::linux`, and the test after this one runs the same operation over
    /// the same location with the mount and without it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_granted_directory_with_a_filesystem_mounted_beneath_it_is_refused_with_the_reason() {
        let fixture = Fixture::create();
        let profile = fixture.service().profile();
        let location = fixture.work().join("location");
        std::fs::create_dir(&location).expect("a location");
        let table = std::fs::read_to_string("/proc/self/mountinfo").expect("the mount table");
        if !table
            .lines()
            .filter_map(|line| line.split(' ').nth(4))
            .any(|point| point.starts_with("/dev/"))
        {
            println!("not exercised: nothing is mounted beneath /dev on this host");
            return;
        }
        let arguments: [&OsStr; 2] = [OsStr::new("config"), OsStr::new("--list")];
        let refusal = profile
            .run(
                &GitRequest::read(&location, &arguments)
                    .reading(&[Path::new("/dev")])
                    .admitted(bounded()),
            )
            .expect_err("a grant with another filesystem mounted beneath it is refused");
        let said = refusal.to_string();
        assert!(
            said.contains("a filesystem is mounted at /dev/") && said.contains("beneath /dev,"),
            "the refusal names the mount point and the granted directory: {said}"
        );
    }

    /// Tells the run of this test inside a mount namespace where the location is.
    #[cfg(target_os = "linux")]
    const INSIDE: &str = "KR_PROJECT_READS_LOCATION_INSIDE_A_MOUNT_NAMESPACE";

    /// A filesystem mounted beneath the operation's own location refuses the invocation.
    ///
    /// No account here can mount anything where the service runs, so the test runs itself again
    /// inside a namespace that bubblewrap makes, with a filesystem mounted beneath the location,
    /// and the refusal is asserted there. A host whose bubblewrap cannot make a namespace does not
    /// exercise it and says so.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_filesystem_mounted_beneath_the_location_refuses_a_bounded_invocation() {
        if let Some(location) = std::env::var_os(INSIDE) {
            inside_the_namespace(Path::new(&location));
            return;
        }
        let Some(bwrap) = ["/usr/bin/bwrap", "/bin/bwrap"]
            .into_iter()
            .map(Path::new)
            .find(|candidate| candidate.is_file())
        else {
            println!("not exercised: this host has no bubblewrap");
            return;
        };
        let makes_one = std::process::Command::new(bwrap)
            .args(["--unshare-user", "--dev-bind", "/", "/", "--", "/bin/true"])
            .status()
            .is_ok_and(|status| status.success());
        if !makes_one {
            println!("not exercised: bubblewrap cannot make a namespace on this host");
            return;
        }
        let work = tempfile::TempDir::new().expect("a directory on the internal disk");
        let location = support::ordinary_repository(work.path(), "location");
        std::fs::create_dir(location.join("mounted")).expect("a directory to mount over");
        // The control: the same bounded status of the same location, here, where nothing is
        // mounted beneath it. Inside the namespace the one difference is the mount.
        let fixture = Fixture::create();
        let profile = fixture.service().profile();
        let repository = OpenedRepository::open(profile, fixture.environment_id(), &location)
            .expect("the repository opens");
        let status: [&OsStr; 2] = [OsStr::new("status"), OsStr::new("--porcelain")];
        let unmounted = profile
            .run(&repository.read(&status).admitted(bounded()))
            .expect("a bounded status over a location with nothing mounted beneath it runs");
        assert!(unmounted.success, "and succeeds: {}", unmounted.stderr);
        let output = std::process::Command::new(bwrap)
            .args(["--unshare-user", "--dev-bind", "/", "/", "--tmpfs"])
            .arg(location.join("mounted"))
            .arg("--setenv")
            .arg(INSIDE)
            .arg(&location)
            .arg("--")
            .arg(std::env::current_exe().expect("this test's own program"))
            .args([
                "--exact",
                "confined::a_filesystem_mounted_beneath_the_location_refuses_a_bounded_invocation",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("the namespace starts");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success() && said.contains("1 passed"),
            "the run inside the namespace passed: {said}"
        );
    }

    /// The half of the test above that runs inside the namespace.
    #[cfg(target_os = "linux")]
    fn inside_the_namespace(location: &Path) {
        let table = std::fs::read_to_string("/proc/self/mountinfo").expect("the mount table");
        let mounted = location.join("mounted");
        assert!(
            table
                .lines()
                .filter_map(|line| line.split(' ').nth(4))
                .any(|point| Path::new(point) == mounted),
            "a filesystem is mounted beneath the location in here"
        );
        let fixture = Fixture::create();
        let profile = fixture.service().profile();
        let repository = OpenedRepository::open(profile, fixture.environment_id(), location)
            .expect("the repository opens");
        let status: [&OsStr; 2] = [OsStr::new("status"), OsStr::new("--porcelain")];
        let refusal = profile
            .run(&repository.read(&status).admitted(bounded()))
            .expect_err("a bounded invocation over a location with a mount beneath it is refused");
        let said = refusal.to_string();
        assert!(
            said.contains(&format!("a filesystem is mounted at {}", mounted.display()))
                && said.contains(&format!("beneath {},", location.display())),
            "the refusal names the mount point and the location: {said}"
        );
        // The owner's own status of the same location is unchanged: the check is made for a caller
        // bounded by a grant. This is not the control, which is the same bounded status outside.
        let owner = profile
            .run(&repository.read(&status))
            .expect("the owner's status starts");
        assert!(owner.success, "the owner's status runs: {}", owner.stderr);
    }

    /// The cases only a macOS host runs: what the host reads outside the system's own paths, the
    /// mount check against a disk image this account attaches, and the support set read from the
    /// load commands of Mach-O files.
    #[cfg(target_os = "macos")]
    mod macos {
        use std::ffi::{OsStr, OsString};
        use std::path::{Path, PathBuf};
        use std::process::Command;

        use kr_project::identity::OpenedRepository;

        use super::{
            Enclosed, Fixture, REFUSED, Reads, assert_refused, bounded, bounded_reads,
            read_as_configuration, run_enclosed, support,
        };

        /// A disk image this account attached at a directory, detached when it goes.
        struct Attached {
            mount: PathBuf,
        }

        impl Attached {
            /// Makes a small image in `scratch` and attaches it at `directory`, or says so and
            /// returns nothing on a host that will not.
            fn at(directory: &Path, scratch: &Path) -> Option<Self> {
                let image = scratch.join("image.dmg");
                let made = Command::new("/usr/bin/hdiutil")
                    .args([
                        "create", "-size", "2m", "-fs", "APFS", "-volname", "krreads",
                    ])
                    .arg(&image)
                    .output()
                    .ok()?;
                if !made.status.success() {
                    println!(
                        "not exercised: this host cannot make a disk image: {}",
                        String::from_utf8_lossy(&made.stderr)
                    );
                    return None;
                }
                let attached = Command::new("/usr/bin/hdiutil")
                    .args(["attach", "-nobrowse", "-noverify", "-mountpoint"])
                    .arg(directory)
                    .arg(&image)
                    .output()
                    .ok()?;
                if !attached.status.success() {
                    println!(
                        "not exercised: this host cannot attach a disk image: {}",
                        String::from_utf8_lossy(&attached.stderr)
                    );
                    return None;
                }
                Some(Self {
                    mount: directory.to_owned(),
                })
            }
        }

        impl Drop for Attached {
            fn drop(&mut self) {
                let detached = Command::new("/usr/bin/hdiutil")
                    .arg("detach")
                    .arg(&self.mount)
                    .arg("-force")
                    .output();
                if !detached.as_ref().is_ok_and(|done| done.status.success()) {
                    eprintln!(
                        "the disk image at {} was not detached: {detached:?}",
                        self.mount.display()
                    );
                }
            }
        }

        /// A secret in the machine's shared temporary directory, and the system's own hosts file,
        /// are not read by a bounded invocation, and are read by the owner and, for the secret,
        /// once the file itself is lent. Neither lies in a tree the profile names. The directory
        /// is not lent: other cases attach disk images beneath their own directories in it, and a
        /// bounded invocation over the whole of it would then be refused for them.
        #[test]
        fn a_secret_in_the_shared_temporary_directory_and_in_the_systems_configuration_is_refused()
        {
            let fixture = Fixture::create();
            let location = fixture.work().join("location");
            std::fs::create_dir(&location).expect("a location");

            let shared = std::env::temp_dir();
            let planted = shared.join(format!("kr-reads-{}.config", uuid::Uuid::new_v4().simple()));
            std::fs::write(&planted, "[secret]\n\tvalue = in-the-shared-directory\n")
                .expect("a file in the shared temporary directory");
            let confined = read_as_configuration(
                &fixture,
                &location,
                &planted,
                Vec::new(),
                bounded_reads(&fixture),
            );
            let granted = read_as_configuration(
                &fixture,
                &location,
                &planted,
                vec![planted.clone()],
                bounded_reads(&fixture),
            );
            std::fs::remove_file(&planted).expect("the planted file goes");
            assert_refused(&confined, "in-the-shared-directory", "the shared directory");
            assert!(
                granted
                    .stdout
                    .contains("secret.value=in-the-shared-directory"),
                "with the file lent it is read: {} {}",
                granted.stdout,
                granted.stderr
            );

            // The hosts file is not configuration, so Git's own complaint about its content is
            // what shows that it was opened and read.
            let hosts = Path::new("/etc/hosts");
            let confined = read_as_configuration(
                &fixture,
                &location,
                hosts,
                Vec::new(),
                bounded_reads(&fixture),
            );
            assert_ne!(confined.status, Some(0));
            assert!(
                confined.stderr.contains(REFUSED) && !confined.stderr.contains("bad config line"),
                "the sandbox refused to open it: {}",
                confined.stderr
            );
            let owner =
                read_as_configuration(&fixture, &location, hosts, Vec::new(), Reads::Everywhere);
            assert!(
                owner.stderr.contains("bad config line"),
                "the owner's reads open it and Git objects to what it holds: {}",
                owner.stderr
            );
        }

        /// The same file, reached by its name through the firmlink that presents the data volume
        /// under the system volume, is refused as the file reached by its own name is.
        #[test]
        fn a_file_outside_every_grant_is_refused_by_the_name_the_data_volume_gives_it() {
            let fixture = Fixture::create();
            let location = fixture.work().join("location");
            std::fs::create_dir(&location).expect("a location");
            let outside = tempfile::TempDir::new().expect("a directory outside the location");
            let secret = std::fs::canonicalize(outside.path())
                .expect("the directory's own name")
                .join("secret.config");
            std::fs::write(&secret, "[secret]\n\tvalue = by-the-volume-name\n")
                .expect("a file outside every grant");
            let through_the_volume = Path::new("/System/Volumes/Data").join(
                secret
                    .strip_prefix("/")
                    .expect("an absolute path has a root"),
            );
            if !through_the_volume.is_file() {
                println!("not exercised: this host presents no data volume under /System");
                return;
            }
            let confined = read_as_configuration(
                &fixture,
                &location,
                &through_the_volume,
                Vec::new(),
                bounded_reads(&fixture),
            );
            assert_refused(&confined, "by-the-volume-name", "the data volume's name");
        }

        /// A disk image this account attaches beneath the operation's own location lets Git read
        /// other storage by a name the profile grants, so the invocation is refused with the
        /// reason while it is there, and runs when it is not. The owner's invocation is not
        /// affected.
        #[test]
        fn a_disk_image_attached_beneath_the_location_refuses_a_bounded_invocation_until_it_is_gone()
         {
            let fixture = Fixture::create();
            let profile = fixture.service().profile();
            let scratch = tempfile::TempDir::new().expect("a directory for the image");
            let location = support::ordinary_repository(fixture.work(), "location");
            let mounted = location.join("mounted");
            std::fs::create_dir(&mounted).expect("a directory to attach at");
            let repository = OpenedRepository::open(profile, fixture.environment_id(), &location)
                .expect("the repository opens");
            let status: [&OsStr; 2] = [OsStr::new("status"), OsStr::new("--porcelain")];

            // The control: the same bounded status of the same location with nothing attached.
            let before = profile
                .run(&repository.read(&status).admitted(bounded()))
                .expect("a bounded status with nothing attached beneath the location runs");
            assert!(before.success, "and succeeds: {}", before.stderr);

            let Some(attached) = Attached::at(&mounted, scratch.path()) else {
                return;
            };
            let refusal = profile
                .run(&repository.read(&status).admitted(bounded()))
                .expect_err("a bounded invocation over a location with a mount beneath it");
            let said = refusal.to_string();
            let mounted = std::fs::canonicalize(&mounted).expect("the mount point's own name");
            let location = std::fs::canonicalize(&location).expect("the location's own name");
            assert!(
                said.contains(&format!("a filesystem is mounted at {}", mounted.display()))
                    && said.contains(&format!("beneath {},", location.display())),
                "the refusal names the mount point and the location: {said}"
            );
            // The check is made for a caller bounded by a grant; the owner's status is unchanged.
            let owner = profile
                .run(&repository.read(&status))
                .expect("the owner's status starts");
            assert!(owner.success, "the owner's status runs: {}", owner.stderr);

            drop(attached);
            let after = profile
                .run(&repository.read(&status).admitted(bounded()))
                .expect("a bounded status after the image is detached runs");
            assert!(after.success, "and succeeds: {}", after.stderr);
        }

        /// A mount beneath a directory the proof itself runs in leaves the host unproved, with the
        /// reason for the daemon's own log, and it qualifies again when the mount is gone.
        #[test]
        fn a_mount_beneath_the_proofs_own_directory_does_not_qualify_until_it_is_gone() {
            use kr_project::service::Refusal;

            let fixture = Fixture::create();
            let scratch = tempfile::TempDir::new().expect("a directory for the image");
            let mounted = fixture.service().profile().home_directory().join("mounted");
            std::fs::create_dir(&mounted).expect("a directory to attach at");
            let proved = fixture.service().qualify();
            assert!(
                proved.qualifies(),
                "this host proves the boundary: {:?}: {}",
                proved.refusal(),
                proved.detail()
            );
            let Some(attached) = Attached::at(&mounted, scratch.path()) else {
                return;
            };
            let refused = fixture.service().qualify();
            assert!(!refused.qualifies());
            assert_eq!(refused.refusal(), Some(Refusal::Invocation));
            assert!(
                refused.detail().contains("a filesystem is mounted at"),
                "the daemon's own log is told what stopped it: {}",
                refused.detail()
            );
            drop(attached);
            assert!(
                fixture.service().qualify().qualifies(),
                "and the host qualifies again when the mount is gone"
            );
        }

        /// A host with no launcher to apply a profile with does not qualify, and the daemon's own
        /// log is told so. The machine is not changed: the answer to where the launcher is, is,
        /// on this thread only.
        #[test]
        fn a_host_with_no_launcher_does_not_qualify_and_says_so() {
            use kr_project::service::Refusal;

            let fixture = Fixture::create();
            let refused = kr_project::boundary::with_launcher_at(
                Path::new("/nonexistent/sandbox-exec"),
                || fixture.service().qualify(),
            );
            assert!(!refused.qualifies());
            assert_eq!(refused.refusal(), Some(Refusal::Invocation));
            assert!(
                refused.detail().contains("no launcher"),
                "the daemon's own log is told what stopped it: {}",
                refused.detail()
            );
            assert!(
                fixture.service().qualify().qualifies(),
                "and the same host qualifies with the launcher it has"
            );
        }

        /// A program in the helper directory an invocation may execute from is executed, and the
        /// same program beside it is not. A Git whose helpers are programs of their own, as
        /// Homebrew's are, asks this of the profile; Xcode's are links to Git itself.
        #[test]
        fn a_program_in_the_helper_directory_runs_and_the_same_program_beside_it_does_not() {
            let fixture = Fixture::create();
            let Some(built) = Built::under(Path::new(env!("CARGO_TARGET_TMPDIR"))) else {
                return;
            };
            let helper = built.root.join("helpers").join("probe");
            std::fs::copy(&built.program, &helper).expect("a copy in the helper directory");
            let reads = Reads::Bounded(std::sync::Arc::new(
                built.support().expect("the set of these programs is named"),
            ));
            let shell = Path::new("/bin/bash");
            let location = fixture.work().join("location");
            std::fs::create_dir_all(&location).expect("a location");
            let run = |program: &Path, reads: Reads| {
                run_enclosed(
                    &fixture,
                    &location,
                    Enclosed {
                        program: shell,
                        arguments: vec![OsString::from("-c"), program.as_os_str().to_owned()],
                        helpers: Vec::new(),
                        readable: Vec::new(),
                        reads,
                        exec_path: Some(built.root.join("helpers")),
                    },
                )
            };
            let ran = run(&helper, reads.clone());
            assert_eq!(ran.status, Some(0), "the helper runs: {}", ran.stderr);
            let beside = run(&built.program, reads);
            assert_ne!(
                beside.status,
                Some(0),
                "the same program beside it does not"
            );
            assert!(
                beside.stderr.contains(REFUSED),
                "the sandbox refused it: {}",
                beside.stderr
            );
        }

        /// The compiler, when the developer tools are installed. The system's `clang` is a
        /// stand-in that offers to install them when they are not, so it is asked for only after
        /// `xcode-select` has said they are.
        fn compiler() -> Option<PathBuf> {
            let developer = Command::new("/usr/bin/xcode-select")
                .arg("-p")
                .output()
                .ok()?;
            let clang = PathBuf::from("/usr/bin/clang");
            (developer.status.success() && clang.is_file()).then_some(clang)
        }

        /// A program and the libraries it loads, built in a directory of its own and taken away
        /// again with it. The program names one library through an rpath that goes through a
        /// link, a second by its absolute path and a third relative to itself. The first names a
        /// fourth relative to itself, and the third names a fifth through the program's own rpath,
        /// which a library it loads inherits, so that every way a name is written is read. A sixth
        /// is linked weakly, which the loader may go without.
        struct Built {
            root: PathBuf,
            program: PathBuf,
            /// The directories the libraries are in, in the order of their paths.
            library_directories: Vec<PathBuf>,
        }

        impl Built {
            /// Builds them under `parent`, or says why not and returns nothing.
            fn under(parent: &Path) -> Option<Self> {
                let clang = compiler().or_else(|| {
                    println!("not exercised: this host has no developer tools to build a library");
                    None
                })?;
                let root = parent.join(format!("kr-reads-{}", uuid::Uuid::new_v4().simple()));
                for name in [
                    "real", "deep", "second", "third", "extra", "weak", "bin", "helpers",
                ] {
                    std::fs::create_dir_all(root.join(name)).expect("a directory to build in");
                }
                let root = std::fs::canonicalize(&root).expect("the directory's own name");
                std::os::unix::fs::symlink("real", root.join("linked"))
                    .expect("a link to the library's directory");
                let source = |name: &str, text: &str| {
                    std::fs::write(root.join(name), text).expect("a source file");
                };
                source("deep.c", "int krdeep_answer(void) { return 42; }\n");
                source(
                    "probe.c",
                    "int krdeep_answer(void);\nint krprobe_answer(void) { return krdeep_answer(); }\n",
                );
                source("second.c", "int krsecond_answer(void) { return 42; }\n");
                source(
                    "third.c",
                    "int krextra_answer(void);\nint krthird_answer(void) { return krextra_answer(); }\n",
                );
                source("extra.c", "int krextra_answer(void) { return 42; }\n");
                source("weak.c", "int krweak_answer(void) { return 42; }\n");
                source(
                    "program.c",
                    "int krprobe_answer(void);\nint krsecond_answer(void);\nint krthird_answer(void);\n\
                     int main(void) {\n\
                         return krprobe_answer() == 42 && krsecond_answer() == 42\n\
                             && krthird_answer() == 42 ? 0 : 1;\n\
                     }\n",
                );
                // Every file is built for both architectures, as the system's own programs are
                // shipped, so the slice for this machine is the one that is read.
                let compile = |arguments: &[&OsStr]| {
                    let output = Command::new(&clang)
                        .args(["-arch", "arm64", "-arch", "x86_64"])
                        .args(arguments)
                        .output()
                        .expect("the compiler starts");
                    assert!(
                        output.status.success(),
                        "the compiler builds it: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                };
                let library =
                    |directory: &str, name: &str, install_name: &str, extra: &[&OsStr]| {
                        let file = root.join(directory).join(format!("lib{name}.dylib"));
                        let source = root.join(format!(
                            "{}.c",
                            if name == "krprobe" {
                                "probe"
                            } else {
                                &name[2..]
                            }
                        ));
                        let mut arguments: Vec<&OsStr> = vec![
                            OsStr::new("-dynamiclib"),
                            OsStr::new("-install_name"),
                            OsStr::new(install_name),
                            OsStr::new("-o"),
                            file.as_os_str(),
                            source.as_os_str(),
                        ];
                        arguments.extend_from_slice(extra);
                        compile(&arguments);
                    };
                library(
                    "deep",
                    "krdeep",
                    "@loader_path/../deep/libkrdeep.dylib",
                    &[],
                );
                library(
                    "real",
                    "krprobe",
                    "@rpath/libkrprobe.dylib",
                    &[
                        OsStr::new(&format!("-L{}", root.join("deep").display())),
                        OsStr::new("-lkrdeep"),
                    ],
                );
                library(
                    "second",
                    "krsecond",
                    &root
                        .join("second")
                        .join("libkrsecond.dylib")
                        .display()
                        .to_string(),
                    &[],
                );
                library("extra", "krextra", "@rpath/libkrextra.dylib", &[]);
                library("weak", "krweak", "@rpath/libkrweak.dylib", &[]);
                library(
                    "third",
                    "krthird",
                    "@executable_path/../third/libkrthird.dylib",
                    &[
                        OsStr::new(&format!("-L{}", root.join("extra").display())),
                        OsStr::new("-lkrextra"),
                    ],
                );
                let program = root.join("bin").join("probe");
                compile(&[
                    OsStr::new("-o"),
                    program.as_os_str(),
                    root.join("program.c").as_os_str(),
                    OsStr::new(&format!("-L{}", root.join("real").display())),
                    OsStr::new("-lkrprobe"),
                    OsStr::new(&format!("-L{}", root.join("second").display())),
                    OsStr::new("-lkrsecond"),
                    OsStr::new(&format!("-L{}", root.join("third").display())),
                    OsStr::new("-lkrthird"),
                    OsStr::new(&format!("-L{}", root.join("weak").display())),
                    OsStr::new("-weak-lkrweak"),
                    OsStr::new("-Wl,-rpath,@loader_path/../linked"),
                    OsStr::new("-Wl,-rpath,@loader_path/../extra"),
                    OsStr::new("-Wl,-rpath,@loader_path/../weak"),
                ]);
                let library_directories = ["deep", "extra", "real", "second", "third", "weak"]
                    .iter()
                    .map(|name| root.join(name))
                    .collect();
                Some(Self {
                    root,
                    program,
                    library_directories,
                })
            }

            /// Returns the support set of the program alone, with no helper directory to read.
            fn support(&self) -> kr_project::error::Result<kr_project::boundary::SupportSet> {
                kr_project::boundary::support_set(
                    &[self.program.as_path()],
                    &self.root.join("helpers"),
                )
            }
        }

        impl Drop for Built {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.root);
            }
        }

        /// Runs the built program inside the boundary with these reads, and reports how it ended.
        fn run_probe(fixture: &Fixture, built: &Built, reads: Reads) -> (Option<i32>, String) {
            let location = fixture.work().join("location");
            std::fs::create_dir_all(&location).expect("a location");
            let outcome = run_enclosed(
                fixture,
                &location,
                Enclosed {
                    program: &built.program,
                    arguments: Vec::<OsString>::new(),
                    helpers: Vec::new(),
                    readable: Vec::new(),
                    reads,
                    exec_path: None,
                },
            );
            (outcome.status, outcome.stderr)
        }

        /// A program's library is named by the directory it is in, resolved through the link its
        /// rpath goes through, and the system's own libraries, which the shared cache supplies, are
        /// named by nothing. The program runs under the set it was given, and does not run under
        /// the set of a program that does not load the library; the owner's run is the control.
        #[test]
        fn a_programs_library_is_granted_by_its_directory_and_the_program_needs_the_grant() {
            let fixture = Fixture::create();
            let parent = Path::new(env!("CARGO_TARGET_TMPDIR"));
            let Some(built) = Built::under(parent) else {
                return;
            };

            let named = built.support().expect("the set of this program is named");
            assert_eq!(
                named.libraries(),
                built.library_directories,
                "the directory each library is in, with the link resolved, and no system directory"
            );
            assert!(named.loaders().is_empty(), "this platform names no loader");

            let (status, stderr) =
                run_probe(&fixture, &built, Reads::Bounded(std::sync::Arc::new(named)));
            assert_eq!(
                status,
                Some(0),
                "the program runs under its own set: {stderr}"
            );

            let (status, stderr) = run_probe(&fixture, &built, bounded_reads(&fixture));
            assert_ne!(
                status,
                Some(0),
                "the program does not run under the set of Git, which lacks its library"
            );
            assert!(
                stderr.contains("Library not loaded") || status.is_none(),
                "the loader could not open the library: {stderr}"
            );

            let (status, stderr) = run_probe(&fixture, &built, Reads::Everywhere);
            assert_eq!(status, Some(0), "the owner's run is the control: {stderr}");

            let git = fixture
                .service()
                .profile()
                .support_set()
                .expect("this host names the support set of its Git");
            for directory in git.libraries() {
                assert!(
                    !directory.starts_with("/usr/lib") && !directory.starts_with("/System"),
                    "the system's libraries come from the shared cache: {}",
                    directory.display()
                );
            }
        }

        /// A library the program links weakly is one the loader goes without when it is not there,
        /// so the set is named without it, and a library that is there is granted as any other.
        #[test]
        fn a_weak_library_that_is_not_there_does_not_refuse_the_set() {
            let Some(built) = Built::under(Path::new(env!("CARGO_TARGET_TMPDIR"))) else {
                return;
            };
            std::fs::remove_file(built.root.join("weak").join("libkrweak.dylib"))
                .expect("the weakly linked library goes");
            let named = built
                .support()
                .expect("a program is named without a library it links weakly");
            let expected: Vec<PathBuf> = built
                .library_directories
                .iter()
                .filter(|directory| !directory.ends_with("weak"))
                .cloned()
                .collect();
            assert_eq!(named.libraries(), expected);
        }

        /// A library in the machine's shared temporary directory is one any program of the account
        /// can replace, so a set that would grant its directory is refused, naming the library.
        #[test]
        fn a_library_in_the_shared_temporary_directory_is_not_granted() {
            let Some(built) = Built::under(&std::env::temp_dir()) else {
                return;
            };
            let refusal = built
                .support()
                .expect_err("a library there is not a support object");
            let said = refusal.to_string();
            assert!(
                said.contains("libkrprobe.dylib")
                    && said.contains("not a directory this host grants as a support directory"),
                "the refusal names the library and the rule: {said}"
            );
        }

        /// A library the program names and the system cannot find leaves the set unnamed, and the
        /// refusal names it.
        #[test]
        fn a_library_that_cannot_be_found_refuses_the_set_by_its_name() {
            let Some(built) = Built::under(Path::new(env!("CARGO_TARGET_TMPDIR"))) else {
                return;
            };
            std::fs::remove_file(built.root.join("real").join("libkrprobe.dylib"))
                .expect("the library goes");
            let refusal = built
                .support()
                .expect_err("a library that is not there cannot be granted");
            assert!(
                refusal.to_string().contains("libkrprobe.dylib"),
                "the refusal names it: {refusal}"
            );
        }
    }
}
