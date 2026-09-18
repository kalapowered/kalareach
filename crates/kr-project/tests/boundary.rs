//! What the boundary around a Git invocation holds, against a writer racing it.
//!
//! The restricted profile reads a repository's configuration and then starts Git, and a writer
//! under the same operating-system account can change the repository in between. These tests do
//! exactly that, through the fixtures' seam, and then require that nothing the writer planted ran,
//! that nothing outside the operation's own directories was written, and that no address was
//! reached that the operation had no business reaching.
//!
//! Each one carries its own control: a planting whose effect is proved by running installed Git
//! against the same repository afterwards, a refusal whose cause is proved by the same command
//! succeeding when the directory is named, and a connection that is refused on one port and made on
//! another. A test that could pass because nothing was planted at all is not evidence.
//!
//! KR-ACC-030, KR-REQ-14.06, KR-REQ-14.21, KR-REQ-14.23 and KR-REQ-14.24.

#![cfg(feature = "git-fixtures")]

mod support;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_project::git::{GitRequest, Interposition, RemoteAccess};
use kr_project::identity::OpenedRepository;
use kr_project::workspace::{PreviewRequest, survey};
use kr_protocol::project::{
    AdoptionFlow, InclusionPolicy, IsolationMechanism, ProjectAdoptParams, ProjectCloneParams,
    RemoteSpecification, RemoteTransport, WorkspaceCreateParams, WorkspaceKind,
};
use kr_protocol::scalars::Nullable;

use support::{
    Fixture, action, actor, destination, empty_the_sentinels, git_raw, include_everything,
    installed_broker, names_in, ordinary_repository, plant_marker, write,
};

/// A repository whose committed attributes name two drivers that nothing defines yet.
///
/// Nothing here is execution-capable: an attribute names a driver and the configuration defines
/// one, so a repository built like this passes every reading the host makes. What the seam does
/// later is supply the definitions, which is the window the boundary exists for.
struct Racing {
    path: PathBuf,
    sentinels: PathBuf,
    marker: PathBuf,
}

impl Racing {
    fn build(work: &Path, name: &str) -> Self {
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
        let sentinels = work.join(format!("{name}-sentinels"));
        let marker = plant_marker(work, name, &sentinels);
        empty_the_sentinels(&sentinels);
        Self {
            path,
            sentinels,
            marker,
        }
    }

    /// Returns the names of every sentinel that exists, which must be none.
    fn escaped(&self) -> Vec<String> {
        names_in(&self.sentinels)
    }

    /// Defines the drivers and writes the hooks, as a writer racing the invocation would.
    ///
    /// One driver names a program inside the repository and one names a program inside the
    /// invocation's own private temporary directory, because the boundary's claim covers both.
    fn plant(&self, temporary: &Path) {
        let inside = self.path.join("planted-driver.sh");
        copy_program(&self.marker, &inside, "driver-inside-the-repository");
        let in_temporary = temporary.join("planted-driver.sh");
        copy_program(
            &self.marker,
            &in_temporary,
            "driver-in-the-temporary-directory",
        );
        for (key, program) in [
            ("filter.inside.clean", &inside),
            ("filter.inside.smudge", &inside),
            ("filter.inside.process", &inside),
            ("diff.inside.textconv", &inside),
            ("filter.temporary.clean", &in_temporary),
            ("filter.temporary.smudge", &in_temporary),
        ] {
            git_raw(
                &self.path,
                [
                    OsStr::new("config"),
                    OsStr::new("--local"),
                    OsStr::new("--"),
                    OsStr::new(key),
                    program.as_os_str(),
                ],
            );
        }
        let hooks = self.path.join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("the repository's own hook directory");
        for hook in [
            "post-checkout",
            "post-merge",
            "pre-auto-gc",
            "post-index-change",
        ] {
            copy_program(&self.marker, &hooks.join(hook), &format!("hook-{hook}"));
        }
    }

    /// Runs installed Git over the same repository and requires the planting to have had an effect.
    ///
    /// Without this the assertions above would pass for a repository where nothing was planted at
    /// all. Installed Git reads the same configuration the seam wrote and runs the driver, which
    /// leaves the sentinel this requires; the sentinels are emptied again afterwards.
    fn require_the_planting_would_have_run(&self) {
        assert_eq!(
            self.escaped(),
            Vec::<String>::new(),
            "the control starts from nothing"
        );
        git_raw(&self.path, ["add", "-A"]);
        let escaped = self.escaped();
        assert!(
            escaped.contains(&"driver-inside-the-repository".to_owned()),
            "installed Git runs the driver the seam defined, so an empty sentinel directory above \
             is evidence that the boundary stopped it rather than that nothing was planted: {escaped:?}"
        );
        empty_the_sentinels(&self.sentinels);
    }
}

/// Writes a program that invokes the marker with a name of its own.
fn copy_program(marker: &Path, destination: &Path, sentinel: &str) {
    std::fs::write(
        destination,
        format!("#!/bin/sh\nexec \"{}\" {sentinel}\n", marker.display()),
    )
    .expect("the program is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(destination)
            .expect("the program's metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(destination, permissions).expect("the program is executable");
    }
}

/// An interposition that plants before every spawn whose description starts with one of these.
fn planting_before(
    racing: Arc<Racing>,
    before: &'static [&'static str],
) -> (Interposition, Arc<AtomicUsize>) {
    let planted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&planted);
    let interposition = Interposition::new(Arc::new(move |described: &str, temporary: &Path| {
        if before.iter().any(|start| described.starts_with(start)) {
            racing.plant(temporary);
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }));
    (interposition, planted)
}

#[test]
fn a_driver_planted_after_the_audit_never_runs_during_a_status_or_a_review_refresh() {
    let mut fixture = Fixture::create();
    let racing = Arc::new(Racing::build(fixture.work(), "racing-read"));
    // The repository is opened first, so its configuration is read while it still defines nothing.
    // Everything the seam writes below therefore lands after the audit this invocation's overrides
    // are built from, which is the window the boundary exists for and the one nothing else closes.
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &racing.path,
    )
    .expect("a repository that defines nothing opens");
    let (interposition, planted) =
        planting_before(Arc::clone(&racing), &["git status", "git diff"]);
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
        planted.load(Ordering::SeqCst) >= 2,
        "the seam planted before the status and before the review refresh"
    );
    assert_eq!(
        racing.escaped(),
        Vec::<String>::new(),
        "nothing planted between the audit and the spawn ran"
    );
    racing.require_the_planting_would_have_run();
}

#[test]
fn a_driver_planted_after_the_audit_never_runs_during_a_worktree_or_a_staged_clone() {
    let mut fixture = Fixture::with_brokers(installed_broker());
    let racing = Arc::new(Racing::build(fixture.work(), "racing-write"));
    let (interposition, planted) = planting_before(
        Arc::clone(&racing),
        &["git worktree", "git clone", "git checkout"],
    );
    fixture.interpose(interposition);

    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "racing-write"),
                label: "racing".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 1)),
        )
        .expect("the repository is adopted")
        .project
        .project_repository_id;

    let created = fixture.service().workspace_create(
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
    // The worktree either lands or is refused because the configuration changed under it. Both are
    // this host's declared answers; what neither may be is a planted driver that ran.
    let _ = created;

    let cloned = fixture.service().project_clone(
        &actor(),
        &ProjectCloneParams {
            destination: destination(fixture.environment_id(), fixture.work(), "cloned"),
            label: "cloned".to_owned(),
            remote: RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::LocalPath,
                url: racing.path.display().to_string(),
                provider: String::new(),
                credential_broker: String::new(),
            },
        },
        Some(&action("project.clone", 3)),
    );
    let _ = cloned;

    assert!(
        planted.load(Ordering::SeqCst) >= 2,
        "the seam planted before a worktree spawn and before a clone spawn: {}",
        planted.load(Ordering::SeqCst)
    );
    assert_eq!(
        racing.escaped(),
        Vec::<String>::new(),
        "nothing planted between the audit and the spawn ran during the worktree or the clone"
    );
    racing.require_the_planting_would_have_run();
}

#[test]
fn a_tree_substituted_at_the_path_is_neither_read_from_nor_written_to() {
    let mut fixture = Fixture::create();
    // Two repositories, each with a file only it has, so what a result describes says which tree it
    // was taken from.
    let verified = ordinary_repository(fixture.work(), "verified");
    write(&verified, "only-in-the-verified-tree.txt", "verified\n");
    git_raw(&verified, ["add", "-A"]);
    git_raw(&verified, ["commit", "-m", "the verified tree"]);
    let substitute = ordinary_repository(fixture.work(), "substitute");
    write(&substitute, "only-in-the-substitute.txt", "substitute\n");
    git_raw(&substitute, ["add", "-A"]);
    git_raw(&substitute, ["commit", "-m", "the substitute"]);
    let moved = fixture.work().join("verified-moved");

    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &verified,
    )
    .expect("the verified repository opens");

    let before = tree_state(&substitute);
    let swap = {
        let verified = verified.clone();
        let substitute = substitute.clone();
        let moved = moved.clone();
        let done = AtomicUsize::new(0);
        Interposition::new(Arc::new(move |described: &str, _temporary: &Path| {
            if !described.starts_with("git status") && !described.starts_with("git worktree") {
                return;
            }
            if done.fetch_add(1, Ordering::SeqCst) > 0 {
                return;
            }
            std::fs::rename(&verified, &moved).expect("the verified tree moves aside");
            std::fs::rename(&substitute, &verified).expect("the substitute takes its name");
        }))
    };
    fixture.interpose(swap);

    // A read. Whatever it produces is the verified tree's: the child was started in the object
    // this host opened rather than at the name it had.
    let arguments: [&OsStr; 3] = [
        OsStr::new("status"),
        OsStr::new("--porcelain=v2"),
        OsStr::new("--untracked-files=all"),
    ];
    let read = fixture
        .service()
        .profile()
        .run(&repository.read(&arguments));
    if let Ok(output) = &read {
        let text = output.text().into_owned();
        assert!(
            !text.contains("only-in-the-substitute"),
            "a result taken after the swap describes the verified tree and never the substitute: \
             {text}"
        );
    }

    // A write. The boundary's rules name the path the verified tree had, and the verified tree is
    // no longer there, so the write is refused: this host's declared answer rather than a write
    // into whatever took the name.
    let outside = fixture.work().join("worktree-after-the-swap");
    let arguments: [&OsStr; 5] = [
        OsStr::new("worktree"),
        OsStr::new("add"),
        OsStr::new("--detach"),
        outside.as_os_str(),
        OsStr::new("HEAD"),
    ];
    let written = fixture
        .service()
        .profile()
        .run(&repository.write(&arguments).writing(&[outside.as_path()]));
    let landed = written.is_ok_and(|output| output.success);

    // Whatever became of the invocation, the substitute holds exactly what it held.
    assert_eq!(
        tree_state(&verified),
        before,
        "the tree that took the name was not written to, whether the invocation landed ({landed}) \
         or was refused"
    );
    // And the host refuses the result afterwards, because the repository is no longer where it was.
    assert!(
        repository.confirm(fixture.service().profile()).is_err(),
        "a repository that is no longer at the path it reported does not have its results served"
    );
    // The verified tree is still whole where it was moved to.
    assert!(moved.join("only-in-the-verified-tree.txt").is_file());
}

/// Returns the sorted names one tree holds and the contents of the file that identifies it.
fn tree_state(path: &Path) -> (Vec<String>, String) {
    let names = names_in(path);
    let identifying = path.join("only-in-the-substitute.txt");
    let contents = std::fs::read_to_string(&identifying).unwrap_or_default();
    (names, contents)
}

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
    support::assert_absent(&outside, "nothing was written outside the boundary");

    // The control: the same command, with the destination named as one this operation owns. A
    // refusal that happened for any other reason would fail here.
    std::fs::create_dir_all(&outside).expect("the destination this operation reserves");
    let permitted = fixture
        .service()
        .profile()
        .run(&repository.write(&arguments).writing(&[outside.as_path()]))
        .expect("the invocation ran");
    assert!(
        permitted.success,
        "the same worktree lands when the operation owns its destination: {}",
        permitted.stderr
    );
    assert!(outside.join("README.md").is_file());
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
    let _: &[&str] = kr_project::boundary::CONNECTION_SHELL;
    let _: InclusionPolicy = include_everything();
}
