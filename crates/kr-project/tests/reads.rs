//! What an invocation for a caller bounded by a grant can read.
//!
//! On Linux such an invocation runs inside one Landlock ruleset with no rule on the whole
//! filesystem. It reads the directories the operation owns, the ones it is lent, Git's own program
//! and helper directory, the four device nodes and the support set named for this host's Git, and
//! nothing else the account can read. Each refusal here sits beside its control: the same
//! operation on the same objects with exactly one restriction lifted, which reads what the refusal
//! did not. Where the refusal is the kernel's, it is shown in the child's own words, as a refusal
//! to open the object, rather than as an exit code.
//!
//! Elsewhere no platform confines what Git reads, and such an invocation is refused with the
//! reason.

#![cfg(feature = "git-fixtures")]

mod support;

use kr_project::git::ReadAdmission;
use support::Fixture;

/// An admission that asks nothing, for an operation performed for a caller bounded by a grant.
fn bounded() -> Option<ReadAdmission> {
    Some(ReadAdmission::new(|| Ok(())).bounded())
}

#[cfg(not(target_os = "linux"))]
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
    assert!(
        refusal
            .to_string()
            .contains("this platform does not confine what Git reads"),
        "the refusal says why: {refusal}"
    );
    // The control: the owner's own invocation of the same command on the same repository runs
    // where this platform runs Git at all.
    #[cfg(target_os = "macos")]
    assert!(
        fixture
            .service()
            .profile()
            .run(&kr_project::git::GitRequest::read(&path, &arguments))
            .expect("the owner's status runs")
            .success
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{OsStr, OsString};
    use std::io::Read as _;
    use std::path::{Path, PathBuf};

    use kr_project::boundary::{Confinement, Invocation, OpenedDirectory, Reach, Reads};
    use kr_project::git::{ConfigurationAudit, GitRequest, RemoteAccess};
    use kr_project::identity::OpenedRepository;

    use super::{Fixture, bounded, support};

    /// What one enclosed child did, in its own words, and the environment it was given.
    struct Outcome {
        status: Option<i32>,
        stdout: String,
        stderr: String,
        environment: Vec<(OsString, OsString)>,
    }

    /// One child to start inside the boundary.
    struct Enclosed<'a> {
        program: &'a Path,
        arguments: Vec<OsString>,
        helpers: Vec<PathBuf>,
        readable: Vec<PathBuf>,
        reads: Reads,
    }

    /// Starts one child inside the boundary as the profile starts Git, and keeps the child's own
    /// standard error rather than reducing it to its class: these tests have to see what the
    /// kernel refused.
    ///
    /// The confinement is built from the profile's own parts, with the profile's own directories
    /// readable as every invocation's are, and the child's temporary directory made for it.
    fn run_enclosed(fixture: &Fixture, working: &Path, enclosed: Enclosed<'_>) -> Outcome {
        let profile = fixture.service().profile();
        let environment_id = fixture.environment_id();
        let temporary = tempfile::TempDir::new().expect("a temporary directory for the child");
        let confinement = Confinement {
            program: enclosed.program.to_owned(),
            exec_path: profile.git().exec_path().to_owned(),
            helpers: enclosed.helpers,
            working: OpenedDirectory::open(environment_id, working, None)
                .expect("the working directory opens"),
            reserved: Vec::new(),
            temporary: OpenedDirectory::open(environment_id, temporary.path(), None)
                .expect("the temporary directory opens"),
            readable: [
                profile.git().program(),
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
        let environment =
            profile.environment(&GitRequest::read(working, &nothing), temporary.path());
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
        let program = fixture.service().profile().git().executable().to_owned();
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
            },
        )
    }

    /// Asserts that one read was the kernel refusing to open the file, and that nothing of it was
    /// read.
    fn assert_refused(outcome: &Outcome, secret: &str, what: &str) {
        assert_ne!(outcome.status, Some(0), "{what}: Git reports the failure");
        assert!(
            outcome.stderr.contains("Permission denied"),
            "{what}: the kernel refused to open it, and Git said {}",
            outcome.stderr
        );
        assert!(
            !outcome.stdout.contains(secret) && !outcome.stderr.contains(secret),
            "{what}: nothing of it was read"
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
        // Placed rather than written here, so no child another test starts can hold it open for
        // writing and have the kernel refuse it as busy, which is not the refusal under test.
        support::place_script(&planted, "#!/bin/sh\necho planted-program-ran\n");
        let shell = Path::new("/bin/sh");
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
                },
            )
        };
        let refused = run(Vec::new());
        assert!(
            !refused.stdout.contains("planted-program-ran"),
            "the planted program did not run"
        );
        assert!(
            refused.stderr.contains("Permission denied"),
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
        let refusal = ConfigurationAudit::take(profile, &path, None, bounded().as_ref())
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
        ConfigurationAudit::take(profile, &path, None, None)
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
    const INSIDE: &str = "KR_PROJECT_READS_LOCATION_INSIDE_A_MOUNT_NAMESPACE";

    /// A filesystem mounted beneath the operation's own location refuses the invocation.
    ///
    /// No account here can mount anything where the service runs, so the test runs itself again
    /// inside a namespace that bubblewrap makes, with a filesystem mounted beneath the location,
    /// and the refusal is asserted there. A host whose bubblewrap cannot make a namespace does not
    /// exercise it and says so.
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
                "linux::a_filesystem_mounted_beneath_the_location_refuses_a_bounded_invocation",
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
}
