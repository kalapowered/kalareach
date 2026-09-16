//! Handle-based filesystem authority, driven from the committed no-escape fixture.
//!
//! Requirement rows closed here: KR-REQ-14.05 and the transfer half of KR-ACC-030.
//!
//! The fixture at `fixtures/transfer/no-escape.json` is the policy in one place: the names the
//! validator accepts and refuses, the tree a lookup runs against, and what each lookup must do.
//! The Unix cases run here. The Windows cases are in the same fixture and are built when the
//! running platform can build them; where it cannot, the case is reported as not exercised rather
//! than counted as passed, and the Windows qualification pass records the result.

mod support;

use std::path::Path;

use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Uuid;
use kr_transfer::{AuthorisedDirectory, Escape, ObjectPolicy, RelativeName};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    names: Vec<NameCase>,
    tree: Vec<Entry>,
    outside: Vec<Entry>,
    lookups: Vec<LookupCase>,
}

#[derive(Debug, Deserialize)]
struct NameCase {
    name: String,
    refusal: String,
}

#[derive(Debug, Deserialize)]
struct Entry {
    kind: String,
    path: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    contents: Option<String>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct LookupCase {
    name: String,
    refusal: String,
    #[serde(default)]
    platforms: Option<Vec<String>>,
}

/// Returns the name this platform is called in the fixture.
const fn platform() -> &'static str {
    if cfg!(windows) { "windows" } else { "unix" }
}

fn applies(platforms: &Option<Vec<String>>) -> bool {
    match platforms {
        None => true,
        Some(names) => names.iter().any(|name| name == platform()),
    }
}

fn fixture() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/transfer/no-escape.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reads {}: {error}", path.display()));
    serde_json::from_str(&text).expect("the fixture is a document this build reads")
}

/// Returns the name of the refusal an outcome is, in the fixture's vocabulary.
fn refusal_of(outcome: &Result<(), Escape>) -> &'static str {
    match outcome {
        Ok(()) => "ok",
        Err(Escape::Empty) => "empty",
        Err(Escape::NotRelative { .. }) => "not_relative",
        Err(Escape::ParentSegment) => "parent_segment",
        Err(Escape::CurrentSegment) => "current_segment",
        Err(Escape::EmptyComponent) => "empty_component",
        Err(Escape::ForbiddenByte { .. }) => "forbidden_byte",
        Err(Escape::ReservedName { .. }) => "reserved_name",
        Err(Escape::TooLong { .. }) => "too_long",
        Err(Escape::Link { .. }) => "link",
        Err(Escape::NotFound { .. }) => "not_found",
        Err(Escape::Unopenable { .. }) => "unopenable",
        Err(Escape::WrongKind { .. }) => "wrong_kind",
        Err(Escape::IdentityChanged { .. }) => "identity_changed",
        Err(Escape::WrongEnvironment { .. }) => "wrong_environment",
        Err(_) => "unopenable",
    }
}

fn environment() -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([12; 16]))
}

/// KR-REQ-14.05: the accepted form of a relative name is the fixture's.
#[test]
fn every_name_in_the_fixture_is_decided_as_the_fixture_says() {
    let fixture = fixture();
    assert_eq!(fixture.id, "KR-ACC-030");
    assert!(fixture.names.len() > 20, "the fixture covers the policy");
    for case in &fixture.names {
        let outcome = RelativeName::parse(&case.name).map(|_| ());
        assert_eq!(
            refusal_of(&outcome),
            case.refusal,
            "{:?} was {outcome:?}",
            case.name
        );
    }
}

/// KR-REQ-14.05, KR-ACC-030: every lookup in the fixture resolves, or is refused, as it says.
#[test]
fn every_lookup_in_the_fixture_resolves_as_the_fixture_says() {
    let fixture = fixture();
    let root = tempfile::tempdir().expect("a temporary directory");
    let inside = root.path().join("authorised");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(&inside).expect("creates the authorised tree");
    std::fs::create_dir_all(&outside).expect("creates the tree outside it");

    for entry in &fixture.outside {
        build(&outside, entry).expect("builds the tree outside the authority");
    }
    // Every object the fixture names for *this* platform has to exist, or the run has not
    // exercised the policy and must not pass as though it had. A case for the other platform is
    // skipped by name, which is a stated exclusion rather than a silent one.
    let mut missing = Vec::new();
    let mut skipped_objects = Vec::new();
    for entry in &fixture.tree {
        if !applies(&entry.platforms) {
            skipped_objects.push(entry.path.clone());
            continue;
        }
        if let Err(reason) = build(&inside, entry) {
            missing.push(format!("{} ({}): {reason}", entry.path, entry.kind));
        }
    }
    assert!(
        missing.is_empty(),
        "these objects the fixture requires on {} could not be created, so the policy was not \
         exercised: {missing:?}",
        platform()
    );

    let authority =
        AuthorisedDirectory::open_root(environment(), &inside).expect("opens the authority");
    let mut exercised = Vec::new();
    let mut skipped = Vec::new();
    for case in &fixture.lookups {
        if !applies(&case.platforms) {
            skipped.push(case.name.clone());
            continue;
        }
        let outcome = RelativeName::parse(&case.name).and_then(|name| {
            authority
                .open_read(&name, ObjectPolicy::ReadableFile)
                .map(|_| ())
        });
        assert_eq!(
            refusal_of(&outcome),
            case.refusal,
            "{:?} was {outcome:?}",
            case.name
        );
        exercised.push(case.name.clone());
    }
    let expected = fixture
        .lookups
        .iter()
        .filter(|case| applies(&case.platforms))
        .count();
    assert_eq!(
        exercised.len(),
        expected,
        "every lookup this platform covers has to run"
    );
    // The other platform's cases are named, so the qualification run there can see which ones it
    // is responsible for rather than inferring them from a quiet pass here.
    println!(
        "{}: {} lookups skipped {skipped:?}, {} objects skipped {skipped_objects:?}",
        platform(),
        skipped.len(),
        skipped_objects.len()
    );
    // Nothing beneath the authority ever reached the tree outside it.
    assert_eq!(
        std::fs::read_to_string(outside.join("secret.txt")).expect("the outside file is intact"),
        "outside the authorised tree"
    );
}

/// KR-REQ-14.05: a component replaced with a link between two lookups is refused at the second.
#[test]
fn a_component_replaced_with_a_link_is_refused_at_the_next_lookup() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let inside = root.path().join("authorised");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(inside.join("src")).expect("creates the authorised tree");
    std::fs::create_dir_all(&outside).expect("creates the tree outside it");
    std::fs::write(inside.join("src/notes.txt"), b"inside").expect("writes the source");
    std::fs::write(outside.join("notes.txt"), b"outside").expect("writes the decoy");
    let authority =
        AuthorisedDirectory::open_root(environment(), &inside).expect("opens the authority");
    let name = RelativeName::parse("src/notes.txt").expect("a valid relative name");
    authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("opens what is there");

    #[cfg(unix)]
    {
        std::fs::remove_dir_all(inside.join("src")).expect("removes the directory");
        std::os::unix::fs::symlink(&outside, inside.join("src")).expect("replaces it with a link");
        assert!(
            matches!(
                authority.open_read(&name, ObjectPolicy::ReadableFile),
                Err(Escape::Link { .. })
            ),
            "the replacement is refused at the open that would have crossed it"
        );
    }
}

/// KR-REQ-14.05: an authorised handle keeps naming the object it opened, whatever happens to the
/// path afterwards, and a scope reopened at a replaced path is refused.
#[test]
fn a_handle_keeps_its_object_and_a_replaced_path_does_not_extend_the_grant() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let original = root.path().join("project");
    std::fs::create_dir(&original).expect("creates the tree");
    std::fs::write(original.join("notes.txt"), b"the recorded tree").expect("writes a file");
    let authority =
        AuthorisedDirectory::open_root(environment(), &original).expect("opens the authority");
    let recorded = authority.identity();
    let name = RelativeName::parse("notes.txt").expect("a valid relative name");

    // What the platform does with an authorised directory whose path is taken away differs, and
    // both answers are the guarantee: the handle keeps its object either way.
    #[cfg(unix)]
    {
        // The tree is renamed away and an unrelated one takes its name.
        std::fs::rename(&original, root.path().join("moved")).expect("renames the tree");
        std::fs::create_dir(&original).expect("creates a different tree");
        std::fs::write(original.join("notes.txt"), b"an unrelated tree").expect("writes a file");
    }
    #[cfg(windows)]
    {
        // A directory handle here is opened without delete sharing, so the platform refuses to
        // move the directory at all while this authority holds it. Error 32 is the sharing
        // violation.
        let refusal = std::fs::rename(&original, root.path().join("moved"))
            .expect_err("an authorised directory cannot be moved while it is held");
        assert_eq!(
            refusal.raw_os_error(),
            Some(32),
            "the refusal is a sharing violation, not something else: {refusal}"
        );
    }

    // The open handle still names what it opened.
    authority.revalidate().expect("the handle is unchanged");
    assert_eq!(read_through(&authority, &name), "the recorded tree");

    // A scope reopened from the recorded path finds a different object and is refused. The
    // authority is released first, because the directory cannot move on Windows while it is held.
    drop(authority);
    #[cfg(windows)]
    {
        std::fs::rename(&original, root.path().join("moved")).expect("renames the released tree");
        std::fs::create_dir(&original).expect("creates a different tree");
        std::fs::write(original.join("notes.txt"), b"an unrelated tree").expect("writes a file");
    }
    let reopened =
        AuthorisedDirectory::open_root(environment(), &original).expect("opens the new tree");
    assert!(matches!(
        reopened.check_identity(recorded),
        Err(Escape::IdentityChanged { .. })
    ));
}

/// Reads one file through an authority, which is the only way a test is allowed to reach it.
fn read_through(authority: &AuthorisedDirectory, name: &RelativeName) -> String {
    use std::io::Read as _;

    let mut file = authority
        .open_read(name, ObjectPolicy::ReadableFile)
        .expect("opens the file the authority names");
    let mut contents = String::new();
    file.handle_mut()
        .read_to_string(&mut contents)
        .expect("reads the file");
    contents
}

/// KR-REQ-14.05: a directory moved out of the authorised tree during a lookup takes the rest of
/// the lookup with it.
///
/// This is the case a component-wise walk from the *previous* component would miss: each open
/// there carries the boundary of whatever it last reached. Every open here carries the boundary of
/// the authorised directory, so the accumulated path stops resolving the moment the prefix leaves
/// it.
#[test]
fn a_directory_moved_out_of_the_tree_takes_the_rest_of_the_lookup_with_it() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let inside = root.path().join("authorised");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(inside.join("src")).expect("creates the authorised tree");
    std::fs::create_dir_all(&outside).expect("creates the tree outside it");
    std::fs::write(inside.join("src/notes.txt"), b"inside").expect("writes the source");
    let authority =
        AuthorisedDirectory::open_root(environment(), &inside).expect("opens the authority");
    let name = RelativeName::parse("src/notes.txt").expect("a valid relative name");
    authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("opens what is there");

    // The intermediate directory, with the file still inside it, is moved out of the tree.
    std::fs::rename(inside.join("src"), outside.join("src")).expect("moves the directory");
    let refusal = authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect_err("the accumulated path no longer resolves beneath the root");
    assert!(
        matches!(refusal, Escape::NotFound { .. }),
        "expected the name to be gone, got {refusal:?}"
    );
    assert_eq!(
        std::fs::read_to_string(outside.join("src/notes.txt")).expect("still there"),
        "inside",
        "and the file that left is untouched"
    );
}

/// KR-REQ-14.05: a rename refuses two authorities that belong to different environments.
#[test]
fn a_rename_refuses_two_environments() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let from = root.path().join("one");
    let to = root.path().join("two");
    std::fs::create_dir_all(&from).expect("creates a tree");
    std::fs::create_dir_all(&to).expect("creates a tree");
    std::fs::write(from.join("payload.bin"), b"bytes").expect("writes the payload");
    let source = AuthorisedDirectory::open_root(environment(), &from).expect("opens the authority");
    let elsewhere =
        AuthorisedDirectory::open_root(EnvironmentId::new(Uuid::from_bytes([200; 16])), &to)
            .expect("opens the authority");
    let name = RelativeName::parse("payload.bin").expect("a valid relative name");
    let refusal = source
        .rename_into(&name, &elsewhere, &name)
        .expect_err("refuses two environments");
    assert!(
        matches!(refusal, Escape::WrongEnvironment { .. }),
        "expected an environment refusal, got {refusal:?}"
    );
    assert!(from.join("payload.bin").exists(), "and nothing moved");
    assert!(!to.join("payload.bin").exists());

    // The same two names inside one environment do move.
    let same = AuthorisedDirectory::open_root(environment(), &to).expect("opens the authority");
    source
        .rename_into(&name, &same, &name)
        .expect("one environment, one authority");
    assert!(to.join("payload.bin").exists());
}

/// KR-REQ-14.05: a handle from one environment is never accepted by another.
#[test]
fn a_handle_from_one_environment_is_never_accepted_by_another() {
    let root = tempfile::tempdir().expect("a temporary directory");
    std::fs::write(root.path().join("notes.txt"), b"inside").expect("writes a file");
    let authority =
        AuthorisedDirectory::open_root(environment(), root.path()).expect("opens the authority");
    let elsewhere = EnvironmentId::new(Uuid::from_bytes([200; 16]));
    assert!(matches!(
        authority.check_environment(elsewhere),
        Err(Escape::WrongEnvironment { .. })
    ));
    let name = RelativeName::parse("notes.txt").expect("a valid relative name");
    let file = authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("opens the descendant");
    assert!(matches!(
        file.check_environment(elsewhere),
        Err(Escape::WrongEnvironment { .. })
    ));
    file.check_environment(environment())
        .expect("its own environment");
}

/// Builds one fixture entry, or says why this platform could not.
fn build(root: &Path, entry: &Entry) -> Result<(), String> {
    let path = root.join(&entry.path);
    match entry.kind.as_str() {
        "directory" => std::fs::create_dir_all(&path).map_err(|error| error.to_string()),
        "file" => std::fs::write(
            &path,
            entry.contents.as_deref().unwrap_or_default().as_bytes(),
        )
        .map_err(|error| error.to_string()),
        "symlink" => symlink(entry, &path),
        "hard_link" => {
            let target = root.join(entry.target.as_deref().unwrap_or_default());
            std::fs::hard_link(&target, &path).map_err(|error| error.to_string())
        }
        "fifo" => fifo(&path),
        "reparse_point" | "reparse_point_file" => reparse_point(entry, root, &path),
        other => Err(format!("{other} is not an object this build creates")),
    }
}

#[cfg(unix)]
fn symlink(entry: &Entry, path: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(entry.target.as_deref().unwrap_or_default(), path)
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn symlink(_entry: &Entry, _path: &Path) -> Result<(), String> {
    Err("this platform's symbolic links are covered by its reparse-point cases".to_owned())
}

#[cfg(unix)]
fn fifo(path: &Path) -> Result<(), String> {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("mkfifo exited with {status}"))
    }
}

#[cfg(not(unix))]
fn fifo(_path: &Path) -> Result<(), String> {
    Err("this platform has no named pipe in the filesystem namespace".to_owned())
}

#[cfg(windows)]
fn reparse_point(entry: &Entry, root: &Path, path: &Path) -> Result<(), String> {
    let target = root.join(entry.target.as_deref().unwrap_or_default());
    if entry.kind == "reparse_point_file" {
        // A file symbolic link needs a privilege this host never asks for. Where it is absent the
        // case is left unexercised.
        return std::os::windows::fs::symlink_file(&target, path)
            .map_err(|error| error.to_string());
    }
    // A directory junction needs no privilege, which is why it is the reparse point this fixture
    // relies on.
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &path.display().to_string(),
            &target.display().to_string(),
        ])
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("mklink exited with {status}"))
    }
}

#[cfg(not(windows))]
fn reparse_point(_entry: &Entry, _root: &Path, _path: &Path) -> Result<(), String> {
    Err("this platform has no reparse points".to_owned())
}

/// KR-REQ-14.05: a component replaced with a link *while* lookups are running never resolves
/// outside the authorised tree.
///
/// The case the between-two-lookups test cannot reach is the replacement that lands inside one
/// resolution. This runs the replacement in a loop beside the lookups and asserts what has to hold
/// whatever the interleaving was: every lookup that succeeded read the authorised tree's own file,
/// and every one that did not was refused.
#[cfg(unix)]
#[test]
fn a_component_swapped_under_running_lookups_never_resolves_outside() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let root = tempfile::tempdir().expect("a temporary directory");
    let inside = root.path().join("authorised");
    let outside = root.path().join("outside");
    std::fs::create_dir_all(inside.join("src")).expect("creates the authorised tree");
    std::fs::create_dir_all(&outside).expect("creates the tree outside it");
    std::fs::write(inside.join("src/notes.txt"), b"inside").expect("writes the source");
    std::fs::write(outside.join("notes.txt"), b"outside").expect("writes the decoy");
    let authority =
        AuthorisedDirectory::open_root(environment(), &inside).expect("opens the authority");
    let name = RelativeName::parse("src/notes.txt").expect("a valid relative name");
    let stop = AtomicBool::new(false);
    let swaps = AtomicUsize::new(0);

    std::thread::scope(|threads| {
        let swapper = threads.spawn(|| {
            let real = inside.join("src");
            let parked = inside.join(".parked");
            // Bounded as well as flagged. An assertion that fails in the lookups below unwinds
            // without setting the flag, and a producer that waited only for the flag would then
            // keep this scope waiting for it for ever.
            for _ in 0..4_000 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                // The real directory is parked and a link to the tree outside takes its name.
                std::fs::rename(&real, &parked).expect("parks the real directory");
                std::os::unix::fs::symlink(&outside, &real).expect("links to the outside tree");
                // And then back again.
                std::fs::remove_file(&real).expect("removes the link");
                std::fs::rename(&parked, &real).expect("restores the real directory");
                swaps.fetch_add(1, Ordering::Relaxed);
            }
        });

        let mut opened = 0_usize;
        let mut refused = 0_usize;
        for _ in 0..400 {
            match authority.open_read(&name, ObjectPolicy::ReadableFile) {
                Ok(mut file) => {
                    use std::io::Read as _;
                    let mut contents = String::new();
                    file.handle_mut()
                        .read_to_string(&mut contents)
                        .expect("reads what was opened");
                    assert_eq!(
                        contents, "inside",
                        "a lookup resolved to the tree outside the authority"
                    );
                    opened += 1;
                }
                Err(escape) => {
                    assert!(
                        matches!(
                            escape,
                            Escape::Link { .. }
                                | Escape::NotFound { .. }
                                | Escape::Unopenable { .. }
                                | Escape::WrongKind { .. }
                                | Escape::IdentityChanged { .. }
                        ),
                        "the refusal names what it found: {escape:?}"
                    );
                    refused += 1;
                }
            }
        }

        stop.store(true, Ordering::Relaxed);
        swapper.join().expect("the swapper did not panic");
        assert_eq!(opened + refused, 400);
        println!(
            "{opened} lookups resolved, {refused} were refused, over {} swaps",
            swaps.load(Ordering::Relaxed)
        );
    });

    // The file outside the authority is exactly as it was.
    assert_eq!(
        std::fs::read_to_string(outside.join("notes.txt")).expect("the outside file is intact"),
        "outside"
    );
}
