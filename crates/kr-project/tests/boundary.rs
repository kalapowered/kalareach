//! What the boundary around a Git invocation holds, against a writer racing it.
//!
//! The restricted profile reads a repository's configuration and then starts Git, and a writer
//! under the same operating-system account can change the repository in between. These tests do
//! exactly that, through the fixtures' seam, and then require that nothing the writer planted ran,
//! that nothing outside the operation's own directories was written, and that no address was
//! reached that the operation had no business reaching.
//!
//! Two things each of them is built to avoid. A planted helper records with a shell redirection
//! into a directory **inside the repository the invocation is for**, which the boundary itself makes
//! writable: so an empty sentinel directory means the helper did not run, rather than that it ran
//! and could not write. And each assertion carries its control — installed Git is run over the same
//! repository afterwards and must leave the sentinel the service's invocation did not, the same
//! command is run with its destination named and must land where the unnamed one was refused, and
//! the same connection is made on a port the transport names and must arrive where the other did
//! not.
//!
//! On Windows the service runs no Git at all, so what this file establishes there is the refusal
//! itself and the name of the mechanism; everything the other tests build is left unbuilt.
//!
//! KR-ACC-030, KR-REQ-14.06, KR-REQ-14.21, KR-REQ-14.23 and KR-REQ-14.24.

#![cfg(feature = "git-fixtures")]
#![cfg_attr(
    windows,
    expect(
        unused_imports,
        dead_code,
        reason = "this platform runs no Git, so only the refusal and the name of the mechanism are \
                  exercised here"
    )
)]

mod support;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_project::boundary::{ObjectIdentity, identity_of};
use kr_project::git::{GitRequest, Interposition, RemoteAccess};
use kr_project::identity::OpenedRepository;
use kr_project::workspace::{PreviewRequest, survey};
use kr_protocol::project::{
    AdoptionFlow, IsolationMechanism, ProjectAdoptParams, ProjectCloneParams, RemoteSpecification,
    RemoteTransport, WorkspaceCreateParams, WorkspaceKind,
};
use kr_protocol::scalars::Nullable;

use support::{
    Fixture, action, actor, assert_absent, destination, git_raw, include_everything,
    installed_broker, names_in, names_in_if_any, ordinary_repository, write,
};

/// Where a planted helper records, inside the repository it was planted in.
///
/// Inside the Git directory, which the boundary makes writable for every invocation on that
/// repository and which no Git command reads as content. A helper that runs can therefore record;
/// a helper that did not run leaves nothing. Without that, "no sentinel" would also be what write
/// confinement alone produces, and the assertion would pass for the wrong reason.
const SENTINELS: &str = ".git/kr-boundary-sentinels";

/// Writes a program that records its own name and exits zero, with no other program involved.
///
/// A shell redirection and nothing else: a recorder that had to run a second program would make
/// "no sentinel" ambiguous between the recorder being refused and the helper being refused.
fn recorder(path: &Path, repository: &Path, name: &str) {
    let sentinels = repository.join(SENTINELS);
    std::fs::create_dir_all(&sentinels).expect("the sentinel directory");
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\necho ran >> \"{}/{name}\"\nexit 0\n",
            sentinels.display()
        ),
    )
    .expect("the program is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(path)
            .expect("the program's metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).expect("the program is executable");
    }
}

/// Returns the sentinels one repository holds, which must be none.
fn escaped(repository: &Path) -> Vec<String> {
    names_in_if_any(&repository.join(SENTINELS))
}

/// Empties a repository's sentinel directory without taking it away.
fn clear(repository: &Path) {
    let sentinels = repository.join(SENTINELS);
    std::fs::create_dir_all(&sentinels).expect("the sentinel directory");
    for name in names_in(&sentinels) {
        std::fs::remove_file(sentinels.join(name)).expect("a sentinel goes");
    }
}

/// Defines the drivers and writes the hooks in one repository, as a writer racing it would.
///
/// One driver is a program inside the repository and one is a program inside the invocation's own
/// private temporary directory, because the boundary's claim covers both. A clean filter, a smudge
/// filter, a text conversion and four hooks: the long-running form of a filter is deliberately not
/// among them, because it speaks a protocol of its own and a program that does not would fail the
/// control below for a reason that has nothing to do with the boundary. What it would execute is
/// the same program by the same path as the clean filter beside it.
fn plant(repository: &Path, temporary: &Path) {
    let inside = repository.join("planted-driver.sh");
    recorder(&inside, repository, "driver-inside-the-repository");
    let in_temporary = temporary.join("planted-driver.sh");
    recorder(
        &in_temporary,
        repository,
        "driver-in-the-temporary-directory",
    );
    for (key, program) in [
        ("filter.inside.clean", &inside),
        ("filter.inside.smudge", &inside),
        ("diff.inside.textconv", &inside),
        ("filter.temporary.clean", &in_temporary),
        ("filter.temporary.smudge", &in_temporary),
    ] {
        git_raw(
            repository,
            [
                OsStr::new("config"),
                OsStr::new("--local"),
                OsStr::new("--"),
                OsStr::new(key),
                program.as_os_str(),
            ],
        );
    }
    let hooks = repository.join(".git/hooks");
    std::fs::create_dir_all(&hooks).expect("the repository's own hook directory");
    for hook in [
        "post-checkout",
        "post-merge",
        "pre-auto-gc",
        "post-index-change",
    ] {
        recorder(&hooks.join(hook), repository, &format!("hook-{hook}"));
    }
}

/// Builds a repository whose committed attributes name drivers that nothing defines yet.
///
/// Nothing here is execution-capable: an attribute names a driver and the configuration defines
/// one, so a repository built like this passes every reading the host makes. What the seam does
/// later is supply the definitions, which is the window the boundary exists for.
fn racing_repository(work: &Path, name: &str) -> PathBuf {
    let path = ordinary_repository(work, name);
    write(
        &path,
        ".gitattributes",
        "*.inside filter=inside diff=inside\n*.temporary filter=temporary\n",
    );
    write(&path, "one.inside", "content for the driver inside\n");
    write(
        &path,
        "two.temporary",
        "content for the driver in the temporary\n",
    );
    git_raw(&path, ["add", "-A"]);
    git_raw(&path, ["commit", "-m", "the attributes and what they name"]);
    // Something uncommitted, so a status has working-tree content to read through a filter.
    write(&path, "one.inside", "changed after the commit\n");
    write(&path, "two.temporary", "changed after the commit\n");
    path
}

/// Runs installed Git over one repository and requires the planting to have had an effect.
///
/// Without this the assertions above it would pass for a repository where nothing was planted at
/// all, or where the recorder could not record. Installed Git reads the same configuration the seam
/// wrote, runs the driver, and the driver leaves the sentinel this requires.
fn require_the_planting_would_have_run(repository: &Path) {
    assert_eq!(
        escaped(repository),
        Vec::<String>::new(),
        "the control starts from nothing"
    );
    git_raw(repository, ["add", "-A"]);
    let left = escaped(repository);
    assert!(
        left.contains(&"driver-inside-the-repository".to_owned()),
        "installed Git runs the driver the seam defined and the driver records where the boundary \
         would have let it, so an empty sentinel directory above is evidence that the boundary \
         stopped it rather than that nothing was planted or nothing could be written: {left:?}"
    );
    clear(repository);
}

/// What one interposition did, so a test can require that it did anything at all.
struct Planting {
    times: Arc<AtomicUsize>,
    into: Arc<std::sync::Mutex<Vec<PathBuf>>>,
}

/// An interposition that plants into the directory an invocation runs in, before chosen spawns.
fn planting_before(before: &'static [&'static str]) -> (Interposition, Planting) {
    let times = Arc::new(AtomicUsize::new(0));
    let into = Arc::new(std::sync::Mutex::new(Vec::new()));
    let counter = Arc::clone(&times);
    let recorded = Arc::clone(&into);
    let interposition = Interposition::new(Arc::new(
        move |described: &str, working: &Path, temporary: &Path| {
            if before.iter().any(|start| described.starts_with(start)) {
                plant(working, temporary);
                counter.fetch_add(1, Ordering::SeqCst);
                let mut recorded = recorded.lock().expect("the record of what was planted");
                if !recorded.iter().any(|held| held == working) {
                    recorded.push(working.to_owned());
                }
            }
        },
    ));
    (interposition, Planting { times, into })
}

// The boundary runs on the platforms that can hold its guarantees; where it refuses, a Git
// invocation is the refusal and there is nothing here to observe.
#[cfg(unix)]
#[test]
fn a_driver_planted_after_the_audit_never_runs_during_a_status_or_a_review_refresh() {
    let mut fixture = Fixture::create();
    let repository_path = racing_repository(fixture.work(), "racing-read");
    // The repository is opened first, so its configuration is read while it still defines nothing.
    // Everything the seam writes below therefore lands after the audit this invocation's overrides
    // are built from, which is the window the boundary exists for and the one nothing else closes.
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &repository_path,
    )
    .expect("a repository that defines nothing opens");
    let (interposition, planting) = planting_before(&["git status", "git diff"]);
    fixture.interpose(interposition);

    let surveyed = survey(
        fixture.service().profile(),
        &repository,
        &PreviewRequest {
            project_repository_id: kr_protocol::ids::ProjectRepositoryId::new(
                kr_protocol::scalars::Uuid::from_bytes([1; 16]),
            ),
            kind: WorkspaceKind::Isolated,
            policy: include_everything(),
            base_revision: "HEAD",
            base_reference: None,
            base_change_set_id: None,
            at_ms: kr_protocol::scalars::TimestampMs::new(1),
        },
    );
    // The status runs, and afterwards the host re-reads the configuration and refuses a result
    // produced under one it did not audit. Both answers are this host's own; what neither may be
    // is a driver that ran, which is what the sentinels below say.
    if let Ok(surveyed) = &surveyed {
        assert!(
            !surveyed.entries.is_empty(),
            "the status found the changes this test made"
        );
    }

    let arguments: [&OsStr; 5] = [
        OsStr::new("diff"),
        OsStr::new("--no-ext-diff"),
        OsStr::new("--no-textconv"),
        OsStr::new("--name-only"),
        OsStr::new("HEAD"),
    ];
    let refreshed = fixture
        .service()
        .profile()
        .run(&repository.read(&arguments))
        .expect("the review refresh runs");
    assert!(
        refreshed.success,
        "the review refresh reads the repository: {}",
        refreshed.stderr
    );

    assert!(
        planting.times.load(Ordering::SeqCst) >= 2,
        "the seam planted before the status and before the review refresh"
    );
    assert_eq!(
        escaped(&repository_path),
        Vec::<String>::new(),
        "nothing planted between the audit and the spawn ran"
    );
    require_the_planting_would_have_run(&repository_path);
}

// The boundary runs on the platforms that can hold its guarantees; where it refuses, a Git
// invocation is the refusal and there is nothing here to observe.
#[cfg(unix)]
#[test]
fn a_driver_planted_after_the_audit_never_runs_during_a_worktree() {
    let mut fixture = Fixture::create();
    let repository_path = racing_repository(fixture.work(), "racing-worktree");
    let (interposition, planting) = planting_before(&["git worktree"]);
    fixture.interpose(interposition);

    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(
                    fixture.environment_id(),
                    fixture.work(),
                    "racing-worktree",
                ),
                label: "racing".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 1)),
        )
        .expect("the repository is adopted")
        .project
        .project_repository_id;

    // The worktree either lands or is refused because the configuration changed under it. Both are
    // this host's declared answers; what neither may be is a planted driver that ran.
    let _ = fixture.service().workspace_create(
        &actor(),
        &WorkspaceCreateParams {
            project_repository_id: project,
            label: "review".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
            policy: include_everything(),
            base_revision: Nullable(None),
            base_change_set_id: Nullable(None),
            destination: Nullable(Some(destination(
                fixture.environment_id(),
                fixture.work(),
                "worktree",
            ))),
            preview_only: false,
        },
        Some(&action("workspace.create", 2)),
    );

    assert!(
        planting.times.load(Ordering::SeqCst) >= 1,
        "the seam planted before the worktree spawn"
    );
    assert_eq!(
        escaped(&repository_path),
        Vec::<String>::new(),
        "nothing planted between the audit and the spawn ran during the worktree"
    );
    require_the_planting_would_have_run(&repository_path);
}

// The boundary runs on the platforms that can hold its guarantees; where it refuses, a Git
// invocation is the refusal and there is nothing here to observe.
#[cfg(unix)]
#[test]
fn a_driver_planted_into_a_clones_own_destination_never_runs_during_its_checkout() {
    // The clone is the one invocation whose boundary holds the shell Git starts its connection
    // through, and the checkout that follows it is the one that consults a repository's attributes.
    // So the planting goes into the destination the clone made, immediately before that checkout:
    // the configuration the checkout runs under is one nothing audited, and the checkout's own
    // execution list holds no shell at all.
    let mut fixture = Fixture::with_brokers(installed_broker());
    let source = racing_repository(fixture.work(), "clone-source");
    let (interposition, planting) = planting_before(&["git checkout"]);
    fixture.interpose(interposition);

    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "cloned"),
                label: "cloned".to_owned(),
                remote: RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: RemoteTransport::LocalPath,
                    url: source.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&action("project.clone", 3)),
        )
        .expect("a clone of an ordinary repository lands");
    assert_eq!(
        cloned.operation.state,
        kr_protocol::project::OperationState::Completed
    );
    assert!(
        planting.times.load(Ordering::SeqCst) >= 1,
        "the seam planted before the checkout that populates the clone"
    );
    let planted_into = planting
        .into
        .lock()
        .expect("the record of what was planted")
        .clone();
    assert_eq!(planted_into.len(), 1, "one destination was planted in");
    // What the seam planted into travelled with the publication: the staged tree is renamed into
    // place, so the sentinel directory it made is under the destination now.
    let published = fixture.work().join("cloned");
    assert_eq!(
        escaped(&published),
        Vec::<String>::new(),
        "nothing planted into the clone's own destination ran during its checkout"
    );
    // The control is planted again at the published name, because the publication moved the tree
    // and the configuration the seam wrote names the program where the staged tree had it. What it
    // establishes is the same: this planting, in this repository, makes installed Git run the
    // driver and the driver record, so the empty sentinel directory above is the boundary's doing.
    plant(&published, &published.join(".git"));
    require_the_planting_would_have_run(&published);
}

// Both swaps rename a directory this host holds open, which every Unix system permits and Windows
// does not; a Windows test of the same claim needs its own shape and the platform to run it on.
#[cfg(unix)]
#[test]
fn a_tree_substituted_at_the_path_is_not_what_a_read_is_taken_from() {
    let mut fixture = Fixture::create();
    let (verified, substitute, moved) = two_repositories(&fixture, "read");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &verified,
    )
    .expect("the verified repository opens");
    let before = tree_state(&substitute);
    fixture.interpose(swapping_before(
        "git status",
        &verified,
        &substitute,
        &moved,
    ));

    let arguments: [&OsStr; 3] = [
        OsStr::new("status"),
        OsStr::new("--porcelain=v2"),
        OsStr::new("--untracked-files=all"),
    ];
    let refusal = fixture
        .service()
        .profile()
        .run(&repository.read(&arguments))
        .expect_err("a result taken where the directory no longer is, is not served");
    // The declared honest result. Git ran inside the object this host opened, and the name it was
    // started at no longer holds that object, so what it produced is refused rather than returned
    // as if the two were the same thing.
    assert_eq!(refusal.code(), kr_protocol::error::ErrorCode::SourceChanged);
    // The tree that took the name holds exactly what it held.
    assert_eq!(
        tree_state(&verified),
        before,
        "the tree that took the name was neither read from nor written to"
    );
    // And the verified tree is whole where it was moved to.
    assert!(moved.join("only-in-the-verified-tree.txt").is_file());
    assert!(moved.join(".git").is_dir());
}

#[cfg(unix)]
#[test]
fn a_tree_substituted_at_the_path_is_not_what_a_write_lands_in() {
    let mut fixture = Fixture::create();
    let (verified, substitute, moved) = two_repositories(&fixture, "write");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &verified,
    )
    .expect("the verified repository opens");
    // A destination that exists and is named as one this operation owns, so nothing but the
    // boundary can be what refuses the write.
    let reserved = fixture.work().join("worktree-across-the-swap");
    std::fs::create_dir_all(&reserved).expect("the destination this operation reserves");
    let identity =
        identity_of(fixture.environment_id(), &reserved).expect("the destination's own object");
    let before = tree_state(&substitute);
    fixture.interpose(swapping_before(
        "git worktree",
        &verified,
        &substitute,
        &moved,
    ));

    let arguments: [&OsStr; 5] = [
        OsStr::new("worktree"),
        OsStr::new("add"),
        OsStr::new("--detach"),
        reserved.as_os_str(),
        OsStr::new("HEAD"),
    ];
    let written = fixture.service().profile().run(
        &repository
            .write(&arguments)
            .writing(&[(reserved.as_path(), identity)]),
    );
    let landed = written.is_ok_and(|output| output.success);

    // Whatever became of the invocation, the tree that took the name holds exactly what it held:
    // its entries, the file that identifies it, and its own head.
    // The substitute now holds the name the verified tree had, which is where it is read from.
    assert_eq!(
        tree_state(&verified),
        before,
        "the tree that took the name was not written to, whether the invocation landed ({landed}) \
         or was refused"
    );
    assert!(
        moved.join("only-in-the-verified-tree.txt").is_file(),
        "and the verified tree is whole where it was moved to"
    );
    assert!(
        repository.confirm(fixture.service().profile()).is_err(),
        "and the host refuses a result from a repository that is no longer where it was"
    );
}

/// Builds a repository and a second one to put at its name, each with a file only it has.
#[cfg(unix)]
fn two_repositories(fixture: &Fixture, name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let verified = ordinary_repository(fixture.work(), &format!("verified-{name}"));
    write(
        &verified,
        "only-in-the-verified-tree.txt",
        "the verified tree\n",
    );
    let substitute = ordinary_repository(fixture.work(), &format!("substitute-{name}"));
    write(
        &substitute,
        "only-in-the-substitute.txt",
        "the substitute\n",
    );
    let moved = fixture.work().join(format!("moved-{name}"));
    (verified, substitute, moved)
}

/// An interposition that puts one tree at another's name immediately before a chosen spawn.
#[cfg_attr(not(unix), expect(dead_code, reason = "only the swap tests use it"))]
///
/// After the invocation has opened and verified every directory it is enclosed around, and before
/// the child exists: the moment the boundary is for.
fn swapping_before(
    before: &'static str,
    verified: &Path,
    substitute: &Path,
    moved: &Path,
) -> Interposition {
    let verified = verified.to_owned();
    let substitute = substitute.to_owned();
    let moved = moved.to_owned();
    let done = AtomicUsize::new(0);
    Interposition::new(Arc::new(
        move |described: &str, _working: &Path, _temporary: &Path| {
            if !described.starts_with(before) || done.fetch_add(1, Ordering::SeqCst) > 0 {
                return;
            }
            std::fs::rename(&verified, &moved).expect("the verified tree moves aside");
            std::fs::rename(&substitute, &verified).expect("the substitute takes its name");
        },
    ))
}

/// Returns what identifies one tree: what it holds, what its Git directory holds, the file that
/// names it, and its head.
#[cfg_attr(not(unix), expect(dead_code, reason = "only the swap tests use it"))]
///
/// The Git directory's own entries are in it because a write into the wrong tree need not change
/// anything in the working tree: `git worktree add` writes a record under `.git/worktrees` and
/// touches nothing else.
fn tree_state(path: &Path) -> (Vec<String>, Vec<String>, String, String) {
    let names = names_in_if_any(path);
    let administrative = names_in_if_any(&path.join(".git"));
    let identifying = std::fs::read_to_string(path.join("only-in-the-substitute.txt"))
        .or_else(|_| std::fs::read_to_string(path.join("only-in-the-verified-tree.txt")))
        .unwrap_or_default();
    let head = std::fs::read_to_string(path.join(".git/HEAD")).unwrap_or_default();
    (names, administrative, identifying, head)
}

// The boundary runs on the platforms that can hold its guarantees; where it refuses, a Git
// invocation is the refusal and there is nothing here to observe.
#[cfg(unix)]
#[test]
fn an_invocation_reaches_only_the_ports_its_own_transport_uses() {
    let fixture = Fixture::create();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener on this machine");
    let port = listener.local_addr().expect("the bound address").port();
    let (arrived, connections) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            // The connection is answered with nothing at all: what this test reads is whether one
            // arrived, and an empty reply ends the attempt without waiting for a timeout.
            drop(stream);
            if arrived.send(()).is_err() {
                return;
            }
        }
    });

    let url = format!("https://127.0.0.1:{port}/repository.git");
    let clone = |access: Option<RemoteAccess<'_>>, into: &str| {
        let arguments: [&OsStr; 5] = [
            OsStr::new("clone"),
            OsStr::new("--template="),
            OsStr::new("--no-checkout"),
            OsStr::new(&url),
            OsStr::new(into),
        ];
        let mut request =
            GitRequest::write(fixture.work(), &arguments).with_deadline(Duration::from_secs(30));
        if let Some(access) = access {
            request = request.with_transport(access);
        }
        let _ = fixture.service().profile().run(&request);
    };
    let https = |port: Option<u16>| RemoteAccess {
        transport: RemoteTransport::Https,
        credential_helper: None,
        ssh_command: None,
        ssh_program: None,
        port,
        remote_name: Some("origin"),
    };

    // The control: a remote operation whose validated URL named this port reaches it.
    clone(Some(https(Some(port))), "permitted");
    connections
        .recv_timeout(Duration::from_secs(30))
        .expect("an operation whose transport names this port reaches the listener");

    // The same command, from an operation whose ports are its transport's own. Nothing arrives.
    clone(Some(https(None)), "refused");
    assert!(
        connections.recv_timeout(Duration::from_secs(5)).is_err(),
        "an operation reaches only the ports its transport uses"
    );

    // And a local operation, which reaches nothing at all. Two things refuse this one — Git's own
    // transport allowlist and the boundary — and this assertion does not distinguish them; the
    // one above is what establishes the boundary's part.
    clone(None, "local");
    assert!(
        connections.recv_timeout(Duration::from_secs(5)).is_err(),
        "a local operation reaches no address"
    );
}

#[cfg(unix)]
#[test]
fn a_remote_operation_reaches_a_listener_at_a_name_rather_than_an_address() {
    // The boundary refuses every way of reaching another program on this machine, which is how a
    // name service cache and a resolver's own interface are reached. What is left is the files and
    // the resolver itself. This establishes that a remote *named* rather than numbered still
    // reaches its listener from inside the boundary — a failure here is the boundary having taken
    // away more than it meant to — and no more than that: the library Git fetches with answers
    // `localhost` out of its own head rather than asking anything, so which resolver would have
    // answered is not what this test decides. The handoff records that gap.
    let fixture = Fixture::create();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener on this machine");
    let port = listener.local_addr().expect("the bound address").port();
    let (arrived, connections) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
            if arrived.send(()).is_err() {
                return;
            }
        }
    });

    let url = format!("https://localhost:{port}/repository.git");
    let arguments: [&OsStr; 5] = [
        OsStr::new("clone"),
        OsStr::new("--template="),
        OsStr::new("--no-checkout"),
        OsStr::new(&url),
        OsStr::new("by-name"),
    ];
    let request = GitRequest::write(fixture.work(), &arguments)
        .with_deadline(Duration::from_secs(30))
        .with_transport(RemoteAccess {
            transport: RemoteTransport::Https,
            credential_helper: None,
            ssh_command: None,
            ssh_program: None,
            port: Some(port),
            remote_name: Some("origin"),
        });
    let _ = fixture.service().profile().run(&request);

    connections
        .recv_timeout(Duration::from_secs(30))
        .expect("a name this machine answers from its own files is turned into an address");
}

// The boundary runs on the platforms that can hold its guarantees; where it refuses, a Git
// invocation is the refusal and there is nothing here to observe.
#[cfg(unix)]
#[test]
fn a_write_outside_the_directories_an_operation_owns_is_refused() {
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "confined");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &source,
    )
    .expect("the repository opens");
    let outside = fixture.work().join("outside-the-boundary");

    let arguments: [&OsStr; 5] = [
        OsStr::new("worktree"),
        OsStr::new("add"),
        OsStr::new("--detach"),
        outside.as_os_str(),
        OsStr::new("HEAD"),
    ];
    let refused = fixture
        .service()
        .profile()
        .run(&repository.write(&arguments))
        .expect("the invocation ran");
    assert!(
        !refused.success,
        "a worktree at a path the operation does not own is refused"
    );
    assert_absent(&outside, "nothing was written outside the boundary");

    // The control: the same command, with the destination named as one this operation owns. A
    // refusal that happened for any other reason would fail here.
    std::fs::create_dir_all(&outside).expect("the destination this operation reserves");
    let identity: ObjectIdentity =
        identity_of(fixture.environment_id(), &outside).expect("the destination's own object");
    let permitted = fixture
        .service()
        .profile()
        .run(
            &repository
                .write(&arguments)
                .writing(&[(outside.as_path(), identity)]),
        )
        .expect("the invocation ran");
    assert!(
        permitted.success,
        "the same worktree lands when the operation owns its destination: {}",
        permitted.stderr
    );
    assert!(outside.join("README.md").is_file());
}

#[cfg(unix)]
#[test]
fn a_destination_substituted_before_the_spawn_is_not_one_this_operation_owns() {
    // The reserved destination is opened and required to be the object the reservation returned,
    // so a directory somebody puts at that name in between is refused before anything starts
    // rather than becoming a directory the boundary lets Git write in. The substitute is made
    // somewhere else and moved in, because a directory made at the same name a moment after the
    // first one was taken away can be the same object again: an identity a filesystem has reused
    // is what this host records as a limit rather than a thing it can see through.
    let fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "reserved");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &source,
    )
    .expect("the repository opens");
    let reserved = fixture.work().join("reserved-destination");
    let theirs = fixture.work().join("reserved-theirs");
    let aside = fixture.work().join("reserved-aside");
    std::fs::create_dir_all(&reserved).expect("the destination this operation reserves");
    std::fs::create_dir_all(&theirs).expect("the directory somebody else made");
    let identity =
        identity_of(fixture.environment_id(), &reserved).expect("the destination's own object");
    std::fs::rename(&reserved, &aside).expect("the reserved destination moves aside");
    std::fs::rename(&theirs, &reserved).expect("another takes its name");

    let arguments: [&OsStr; 5] = [
        OsStr::new("worktree"),
        OsStr::new("add"),
        OsStr::new("--detach"),
        reserved.as_os_str(),
        OsStr::new("HEAD"),
    ];
    let refusal = fixture
        .service()
        .profile()
        .run(
            &repository
                .write(&arguments)
                .writing(&[(reserved.as_path(), identity)]),
        )
        .expect_err("a destination that is not the object the record names is refused");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::SourceChanged,
        "and it is refused as an identity that changed: {refusal}"
    );
    assert_eq!(
        names_in(&reserved),
        Vec::<String>::new(),
        "and nothing was written into the directory that took the name"
    );
}

#[test]
fn only_an_invocation_that_reaches_a_repository_may_execute_a_shell() {
    // Git builds two things as command strings and starts them through the system shell: its
    // connection to a repository over its own transport, and its call to a credential helper. Both
    // belong to an invocation that reaches a remote or another repository, and every one of those
    // is a clone that checks nothing out. What this establishes is which invocations carry the
    // shell at all; that an authenticated fetch reaches its helper needs a server that asks for a
    // credential, which nothing here has.
    let fixture = Fixture::create();
    let profile = fixture.service().profile();
    let arguments: [&OsStr; 2] = [OsStr::new("status"), OsStr::new("--porcelain=v2")];
    let read = GitRequest::read(fixture.work(), &arguments);
    let list = profile.execution_list(&read);
    assert_eq!(
        list.len(),
        1,
        "a read executes Git and the helpers under Git's own directory and nothing else: {list:?}"
    );

    let helper = profile.git().exec_path().join("git-credential-cache");
    for transport in [
        RemoteTransport::LocalPath,
        RemoteTransport::Ssh,
        RemoteTransport::Https,
    ] {
        let reaching = GitRequest::write(fixture.work(), &arguments).with_transport(RemoteAccess {
            transport,
            credential_helper: Some(helper.as_os_str()),
            ssh_command: None,
            ssh_program: None,
            port: None,
            remote_name: Some("origin"),
        });
        let list = profile.execution_list(&reaching);
        assert!(
            list.iter().any(|program| program.ends_with("sh")
                || program
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("sh"))),
            "an invocation that reaches a repository can start the connection and the credential \
             helper Git builds as command strings: {transport:?} {list:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_destination_substituted_after_the_boundary_was_built_is_the_declared_refusal() {
    // The other half of the destination case: not a substitution before the invocation opened it,
    // which is refused before anything starts, but one made after it was opened and verified, while
    // the boundary's own rules already named it. The rules are written against paths on this
    // platform, so the substitute is a directory those rules permit; what makes that answerable is
    // that every directory an invocation was enclosed around is required to still be that object
    // before anything the child produced is used.
    let mut fixture = Fixture::create();
    let source = ordinary_repository(fixture.work(), "reserved-late");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &source,
    )
    .expect("the repository opens");
    let reserved = fixture.work().join("reserved-late-destination");
    let theirs = fixture.work().join("theirs");
    std::fs::create_dir_all(&reserved).expect("the destination this operation reserves");
    // Empty, so that nothing but this host's own answer decides the outcome: Git refuses a
    // destination that holds something, and a test where it did that would say nothing about the
    // boundary.
    std::fs::create_dir_all(&theirs).expect("the directory somebody else made");
    let identity =
        identity_of(fixture.environment_id(), &reserved).expect("the destination's own object");
    let aside = fixture.work().join("reserved-late-aside");

    let swap = {
        let reserved = reserved.clone();
        let theirs = theirs.clone();
        let aside = aside.clone();
        let done = AtomicUsize::new(0);
        Interposition::new(Arc::new(
            move |described: &str, _working: &Path, _temporary: &Path| {
                if !described.starts_with("git worktree") || done.fetch_add(1, Ordering::SeqCst) > 0
                {
                    return;
                }
                std::fs::rename(&reserved, &aside).expect("the reserved destination moves aside");
                std::fs::rename(&theirs, &reserved).expect("another takes its name");
            },
        ))
    };
    fixture.interpose(swap);

    let arguments: [&OsStr; 5] = [
        OsStr::new("worktree"),
        OsStr::new("add"),
        OsStr::new("--detach"),
        reserved.as_os_str(),
        OsStr::new("HEAD"),
    ];
    let refusal = fixture
        .service()
        .profile()
        .run(
            &repository
                .write(&arguments)
                .writing(&[(reserved.as_path(), identity)]),
        )
        .expect_err("a destination that changed under the invocation is not served");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::SourceChanged,
        "and it is refused as an identity that changed: {refusal}"
    );
    // What this does not say is that nothing was written into the directory that took the name.
    // The rules two of the three mechanisms take are written against paths, so a directory put at
    // one of those names while Git ran is one those rules still permitted, and Git was given that
    // name as an argument. The declared refusal is the answer to that, and it is what this asserts;
    // `crates/kr-project/README.md` says the same in its own words.
    assert_eq!(
        names_in(&aside),
        Vec::<String>::new(),
        "and the object this host reserved, wherever its name went, holds nothing new"
    );
}

#[cfg(unix)]
#[test]
fn a_git_directory_replaced_inside_the_tree_is_the_declared_refusal() {
    // A directory put *inside* a tree the operation owns is inside a tree the operation owns, and
    // no confinement that grants a tree can refuse part of it. So this is not a case the boundary
    // prevents; it is one the identity checks answer. What the test establishes is that the answer
    // is this host's declared refusal rather than a result taken from a repository nobody recorded.
    let mut fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "replaced-git");
    let theirs = ordinary_repository(fixture.work(), "replaced-git-theirs");
    let repository =
        OpenedRepository::open(fixture.service().profile(), fixture.environment_id(), &path)
            .expect("the repository opens");

    let swap = {
        let ours = path.join(".git");
        let aside = fixture.work().join("replaced-git-aside");
        let theirs = theirs.join(".git");
        let done = AtomicUsize::new(0);
        Interposition::new(Arc::new(
            move |described: &str, _working: &Path, _temporary: &Path| {
                if !described.starts_with("git status") || done.fetch_add(1, Ordering::SeqCst) > 0 {
                    return;
                }
                std::fs::rename(&ours, &aside).expect("the repository's own directory moves aside");
                std::fs::rename(&theirs, &ours).expect("another takes its name");
            },
        ))
    };
    fixture.interpose(swap);

    let arguments: [&OsStr; 2] = [OsStr::new("status"), OsStr::new("--porcelain=v2")];
    let refusal = fixture
        .service()
        .profile()
        .run(&repository.read(&arguments))
        .expect_err("a result taken against a repository nobody recorded is not served");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::SourceChanged,
        "and it is refused as an identity that changed: {refusal}"
    );
}

#[cfg(unix)]
#[test]
fn a_substitution_put_back_before_the_check_is_a_limit_this_host_states() {
    // Two readings cannot tell a change made and undone from no change at all. This is that case,
    // written down, and it is the whole of it: another repository holds the name `.git` for the
    // entire run, so the answer served is that repository's, and it is put back before this host
    // looks again, so nothing is refused. Nothing here is a guarantee; it is the shape of the
    // limit, so that a later change which closed it would fail this test and say so.
    let mut fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "restored");
    let theirs = ordinary_repository(fixture.work(), "restored-theirs");
    // Their repository is one commit further on, which is how the answer served can be told apart
    // from the one this repository would have given.
    write(&theirs, "theirs.txt", "not in the other repository\n");
    git_raw(&theirs, ["add", "-A"]);
    git_raw(
        &theirs,
        ["commit", "-m", "the other repository's own commit"],
    );
    let ours_head = git_raw(&path, ["rev-parse", "HEAD"]).trim().to_owned();
    let theirs_head = git_raw(&theirs, ["rev-parse", "HEAD"]).trim().to_owned();
    assert_ne!(ours_head, theirs_head, "the two repositories differ");

    let repository =
        OpenedRepository::open(fixture.service().profile(), fixture.environment_id(), &path)
            .expect("the repository opens");

    let ours_git = path.join(".git");
    let aside = fixture.work().join("restored-aside");
    let theirs_git = theirs.join(".git");
    let swap = {
        let (ours, moved, other) = (ours_git.clone(), aside.clone(), theirs_git.clone());
        let done = AtomicUsize::new(0);
        let before = Interposition::new(Arc::new(
            move |described: &str, _working: &Path, _temporary: &Path| {
                if !described.starts_with("git rev-parse")
                    || done.fetch_add(1, Ordering::SeqCst) > 0
                {
                    return;
                }
                std::fs::rename(&ours, &moved).expect("the repository's own directory moves aside");
                std::fs::rename(&other, &ours).expect("another takes its name");
            },
        ));
        let (ours, moved, other) = (ours_git.clone(), aside.clone(), theirs_git.clone());
        before.and_after(Arc::new(
            move |_described: &str, _working: &Path, _temporary: &Path| {
                if !moved.exists() {
                    return;
                }
                std::fs::rename(&ours, &other).expect("the other repository goes back to its own");
                std::fs::rename(&moved, &ours).expect("and this one comes back to its name");
            },
        ))
    };
    fixture.interpose(swap);

    let arguments: [&OsStr; 2] = [OsStr::new("rev-parse"), OsStr::new("HEAD")];
    let served = fixture
        .service()
        .profile()
        .run(&repository.read(&arguments))
        .expect(
            "every identity this host recorded is the identity it finds, so nothing is refused",
        );
    assert_eq!(
        String::from_utf8_lossy(&served.stdout).trim(),
        theirs_head,
        "and the answer served is the other repository's, which is the limit: {}",
        served.stderr
    );
    // The repository is back at its own name, which is why the reading after the run saw nothing.
    assert_eq!(
        git_raw(&path, ["rev-parse", "HEAD"]).trim(),
        ours_head,
        "and the tree on disk is this repository's again"
    );
}

#[cfg(windows)]
#[test]
fn a_platform_whose_mechanisms_cannot_hold_the_guarantees_runs_no_git() {
    // This platform's application container cannot keep a repository from being executed from, and
    // cannot bound which ports a remote operation reaches. So the service refuses rather than
    // claiming a boundary it does not have, and says which guarantee it cannot make.
    let fixture = Fixture::create();
    let arguments: [&OsStr; 2] = [OsStr::new("status"), OsStr::new("--porcelain=v2")];
    let refusal = fixture
        .service()
        .profile()
        .run(&GitRequest::read(fixture.work(), &arguments))
        .expect_err("no repository operation runs on this platform");
    let said = refusal.to_string();
    assert!(
        said.contains("executed") && said.contains("ports"),
        "and it names both guarantees it cannot make: {said}"
    );
    assert!(kr_project::boundary::MECHANISM.starts_with("none"));
}

#[test]
fn every_class_of_invocation_names_what_encloses_it() {
    // A record a person reads says which mechanism held the invocation, rather than leaving them
    // to infer it from the platform.
    assert!(!kr_project::boundary::MECHANISM.is_empty());
    assert!(
        !kr_project::boundary::MECHANISM.contains("detect"),
        "the boundary is what prevents, not what notices: {}",
        kr_project::boundary::MECHANISM
    );
}
