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

/// KR-REQ-14.29: a file's own protection is asked of the handle this host holds on it.
///
/// Both halves matter. An ordinary file carries its mode bits and nothing else, and a caller that
/// replaces it takes nothing away. A file somebody gave an access-control list carries protection
/// no mode says, and a caller that replaces it would.
#[cfg(unix)]
#[test]
fn a_file_says_through_its_own_handle_whether_it_carries_an_access_control_list() {
    let root = tempfile::tempdir().expect("a directory");
    let authority =
        AuthorisedDirectory::open_root(environment(), root.path()).expect("the authority opens");
    let name = RelativeName::parse("ordinary.txt").expect("a name");
    std::fs::write(root.path().join("ordinary.txt"), b"content\n").expect("a file");

    let file = authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("it opens");
    assert!(
        !file.carries_access_control(),
        "a file whose protection is its mode bits alone carries no list"
    );
    drop(file);

    // The other half needs the platform's own tool. Where it is not installed, this says so rather
    // than reporting a case it did not run.
    let listed = root.path().join("listed.txt");
    std::fs::write(&listed, b"content\n").expect("a second file");
    let who = std::env::var("USER").unwrap_or_else(|_| "root".to_owned());
    let given = if cfg!(target_os = "macos") {
        std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(format!("{who} allow read"))
            .arg(&listed)
            .status()
    } else {
        std::process::Command::new("setfacl")
            .arg("-m")
            .arg(format!("u:{who}:r"))
            .arg(&listed)
            .status()
    };
    match given {
        Ok(status) if status.success() => {
            let second = RelativeName::parse("listed.txt").expect("a name");
            let file = authority
                .open_read(&second, ObjectPolicy::ReadableFile)
                .expect("it opens");
            assert!(
                file.carries_access_control(),
                "a file with a list says so through its own handle"
            );
        }
        _ => println!(
            "not exercised: this platform's access-control tool did not run, so only the \
             no-list half of this case was checked"
        ),
    }
}

/// KR-REQ-14.05: a name resolves through directories on this authority's own mount, and one on
/// another mount is refused before anything beneath it is reached.
///
/// A link is not the only way a path reaches content the path does not name. A directory mounted
/// over a name inside the tree holds another tree entirely, and the path that gets there crosses
/// nothing a no-follow open would see. So the mount is compared as the object is, and a name that
/// resolves through another one does not resolve.
#[test]
fn a_name_that_resolves_through_another_mount_is_refused() {
    let root = tempfile::tempdir().expect("a temporary directory");
    std::fs::create_dir_all(root.path().join("src/inner")).expect("creates the tree");
    std::fs::write(root.path().join("src/inner/notes.txt"), b"inside").expect("writes a file");
    let authority = AuthorisedDirectory::open_root(environment(), root.path())
        .and_then(AuthorisedDirectory::confined_to_one_mount)
        .expect("opens the authority, confined to one mount");

    // One mount, which is the ordinary case and stays ordinary.
    let inner = RelativeName::parse("src/inner").expect("a valid relative name");
    let held = authority.subdirectory(&inner).expect("opens what is there");
    assert_eq!(
        held.mount(),
        authority.mount(),
        "a directory of the tree is on the tree's own mount"
    );
    let name = RelativeName::parse("src/inner/notes.txt").expect("a valid relative name");
    authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("reads through directories on one mount");

    // A boundary this host already carries, asked for through the directory that holds it. Two
    // filesystems is a boundary any host can see, so where there is one the refusal is required
    // rather than hoped for; where the platform has none to cross, this says so.
    let Ok(top) = AuthorisedDirectory::open_root(environment(), Path::new("/"))
        .and_then(AuthorisedDirectory::confined_to_one_mount)
    else {
        println!("not exercised: this platform would not open the root directory");
        return;
    };
    let Ok(here) = std::fs::metadata("/") else {
        println!("not exercised: this platform would not describe its root directory");
        return;
    };
    let Ok(there) = std::fs::metadata("/dev") else {
        println!("not exercised: this platform has no /dev to cross into");
        return;
    };
    if device_of(&here) == device_of(&there) {
        println!("not exercised: this host puts /dev on the filesystem that holds /");
        return;
    }
    let device = RelativeName::parse("dev").expect("a valid relative name");
    assert!(
        matches!(top.subdirectory(&device), Err(Escape::CrossedMount { .. })),
        "a directory on another filesystem is refused, not opened"
    );
    let beneath = RelativeName::parse("dev/null").expect("a valid relative name");
    assert!(
        matches!(
            top.open_read(&beneath, ObjectPolicy::ReadableFile),
            Err(Escape::CrossedMount { .. })
        ),
        "a read refuses at the directory that crosses the mount, before what is under it"
    );
    assert!(
        matches!(top.probe(&beneath), Err(Escape::CrossedMount { .. })),
        "so does a question about what is under it"
    );

    // And an authority that asked for none of this reads across the same boundary as before.
    let ordinary =
        AuthorisedDirectory::open_root(environment(), Path::new("/")).expect("opens the root");
    ordinary
        .subdirectory(&device)
        .expect("an authority that is not confined resolves across a mount as it always did");
}

/// Returns the device an object is on, which is how this test knows a boundary exists at all.
#[cfg(unix)]
fn device_of(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.dev()
}

#[cfg(windows)]
fn device_of(_metadata: &std::fs::Metadata) -> u64 {
    0
}

/// KR-REQ-14.05: a mount placed while names are being resolved never reaches the tree it covers.
///
/// This is the case the descent exists for. A mount is not a link: nothing in the path says one is
/// there, and a resolution that starts again after a check can cross one that appeared in between.
/// The descent holds each directory it checked and opens the next component in it, so a mount that
/// arrives after a directory was opened cannot redirect what is read from it, and one that is
/// there when the directory is opened is refused by the mount comparison. Either way the bytes of
/// the covering tree are never returned.
///
/// It needs a mount namespace this account owns. Where the host does not allow one, the case says
/// it was not exercised rather than reporting a result it did not produce.
#[cfg(target_os = "linux")]
#[test]
fn a_mount_placed_while_reads_resolve_never_reaches_the_other_tree() {
    if std::env::var_os("KR_AUTHORITY_MOUNT_RACE").is_some() {
        mount_race();
        return;
    }
    let probe = std::process::Command::new("unshare")
        .args(["-r", "-m", "--", "true"])
        .status();
    if !probe.is_ok_and(|status| status.success()) {
        println!("not exercised: this host does not give this account a mount namespace");
        return;
    }
    let binary = std::env::current_exe().expect("the test binary");
    let status = std::process::Command::new("unshare")
        .args(["-r", "-m", "--"])
        .arg(binary)
        .args(["--exact", "--nocapture", "--test-threads=1"])
        .arg("a_mount_placed_while_reads_resolve_never_reaches_the_other_tree")
        .env("KR_AUTHORITY_MOUNT_RACE", "1")
        .status()
        .expect("the test binary runs inside a mount namespace");
    assert!(
        status.success(),
        "the reads inside the mount namespace did not hold: {status}"
    );
}

/// The half that runs inside the mount namespace.
#[cfg(target_os = "linux")]
fn mount_race() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let root = tempfile::tempdir().expect("a temporary directory");
    std::fs::create_dir_all(root.path().join("history")).expect("the tree's own directory");
    std::fs::write(root.path().join("history/main"), b"inside").expect("the tree's own file");
    std::fs::create_dir_all(root.path().join("elsewhere")).expect("the covering tree");
    std::fs::write(root.path().join("elsewhere/main"), b"covering").expect("its own file");
    let authority = AuthorisedDirectory::open_root(environment(), root.path())
        .and_then(AuthorisedDirectory::confined_to_one_mount)
        .expect("opens the authority, confined to one mount");
    let name = RelativeName::parse("history/main").expect("a valid relative name");
    let stop = AtomicBool::new(false);
    let placed = AtomicUsize::new(0);

    std::thread::scope(|threads| {
        let mounter = threads.spawn(|| {
            let onto = root.path().join("history");
            let from = root.path().join("elsewhere");
            for _ in 0..2_000 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if rustix::mount::mount_bind(&from, &onto).is_err() {
                    break;
                }
                placed.fetch_add(1, Ordering::Relaxed);
                if rustix::mount::unmount(&onto, rustix::mount::UnmountFlags::DETACH).is_err() {
                    break;
                }
            }
        });

        let mut read = 0_usize;
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
                        "a read returned the bytes of the tree mounted over this one"
                    );
                    read += 1;
                }
                Err(escape) => {
                    assert!(
                        matches!(
                            escape,
                            Escape::CrossedMount { .. }
                                | Escape::NotFound { .. }
                                | Escape::Unopenable { .. }
                                | Escape::Link { .. }
                                | Escape::WrongKind { .. }
                        ),
                        "the refusal names what it found: {escape:?}"
                    );
                    refused += 1;
                }
            }
        }

        stop.store(true, Ordering::Relaxed);
        mounter.join().expect("the mounter did not panic");
        let mounts = placed.load(Ordering::Relaxed);
        assert_eq!(read + refused, 400);
        if mounts == 0 {
            println!("not exercised: this namespace would not place a bind mount");
        } else {
            println!("{read} reads resolved, {refused} were refused, over {mounts} mounts");
        }
    });
}
