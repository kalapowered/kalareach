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
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    assert_eq!(
        file.access_control().expect("reads access control"),
        kr_transfer::AccessControl::None,
        "ordinary file has no access-control list"
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    assert_eq!(
        file.access_control().expect("reads access control"),
        kr_transfer::AccessControl::Unsupported,
        "ordinary file reports Unsupported on non-Apple non-Linux platform"
    );
    drop(file);

    // The other half needs a file with a list. The list is built here and written through the
    // file's own descriptor, so the case runs on every host this crate supports rather than only
    // on one with the platform's command-line tool installed.
    let listed = root.path().join("listed.txt");
    std::fs::write(&listed, b"content\n").expect("a second file");
    let second = RelativeName::parse("listed.txt").expect("a name");
    match give_an_access_control_list(&authority, &second) {
        Some(acl) => {
            let file = authority
                .open_read(&second, ObjectPolicy::ReadableFile)
                .expect("it opens");
            assert!(
                file.carries_access_control(),
                "a file with a list says so through its own handle"
            );
            assert_eq!(
                file.access_control().expect("reads access control"),
                acl,
                "the list read through the handle is the one the file was given"
            );
            // The entries themselves, not merely the fact of them: a list that came back with the
            // right number of entries and none of their rights would pass everything else here.
            #[cfg(target_os = "macos")]
            {
                let kr_transfer::AccessControl::Apple(apple) = &acl else {
                    panic!("this platform's list is an Apple list");
                };
                assert_eq!(apple.entry_count(), 2, "both entries came back");
                let raw = apple.as_bytes();
                assert_eq!(
                    u32::from_ne_bytes(raw[60..64].try_into().expect("four bytes")),
                    1,
                    "the first entry still allows"
                );
                assert_eq!(
                    u32::from_ne_bytes(raw[64..68].try_into().expect("four bytes")),
                    0x0000_0002,
                    "the right it allows came back"
                );
                assert_eq!(
                    u32::from_ne_bytes(raw[84..88].try_into().expect("four bytes")),
                    2,
                    "the second entry still denies"
                );
                assert_eq!(
                    u32::from_ne_bytes(raw[88..92].try_into().expect("four bytes")),
                    0x0000_0400,
                    "the right it denies came back"
                );
            }
            drop(file);

            // Restoring the read access-control list onto a second file descriptor sets the same list.
            let target_name = RelativeName::parse("target.txt").expect("a name");
            std::fs::write(root.path().join("target.txt"), b"target\n").expect("a target file");
            let target = authority
                .open_write(&target_name)
                .expect("opens target write");
            assert!(!target.carries_access_control());
            target
                .set_access_control(&acl)
                .expect("restores access-control list");
            drop(target);

            // Re-read target and verify it matches the source list.
            let target_read = authority
                .open_read(&target_name, ObjectPolicy::ReadableFile)
                .expect("opens target read");
            assert!(target_read.carries_access_control());
            assert_eq!(
                target_read.access_control().expect("reads target acl"),
                acl,
                "restored access-control list matches the source exactly"
            );
            drop(target_read);

            // Clearing the access-control list leaves the file with no list.
            let target_clear = authority
                .open_write(&target_name)
                .expect("opens target write");
            target_clear
                .clear_access_control()
                .expect("clears access-control list");
            drop(target_clear);

            let target_cleared = authority
                .open_read(&target_name, ObjectPolicy::ReadableFile)
                .expect("opens target read");
            assert!(
                !target_cleared.carries_access_control(),
                "cleared file carries no access-control list"
            );
            assert_eq!(
                target_cleared.access_control().expect("reads cleared acl"),
                kr_transfer::AccessControl::None
            );
        }
        None => println!(
            "not exercised: this platform did not take an access-control list, so only the \
             no-list half of this case was checked"
        ),
    }
}

/// Puts an access-control list on one file through its own descriptor, and returns what the
/// platform reports afterwards.
///
/// The list is built here rather than asked of the platform's command-line tool. That tool is a
/// package a host need not have, and a case that quietly does nothing where the package is missing
/// is a case that proves nothing on the machine that most needs it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn give_an_access_control_list(
    authority: &AuthorisedDirectory,
    name: &RelativeName,
) -> Option<kr_transfer::AccessControl> {
    let file = authority.open_write(name).ok()?;
    #[cfg(target_os = "macos")]
    let wanted = {
        // This platform's external representation: a 44-byte header declaring how many entries
        // follow, then 24 bytes an entry, each one the user or group it applies to (16 bytes),
        // what kind of entry it is, and the rights it decides. Two entries, one allowing and one
        // denying, so a list that lost a kind, a right or an entry would be seen to have. What
        // the second entry denies is deliberately not deletion: this platform checks that right
        // against the file a rename replaces, so denying it would stop the very replacement these
        // cases are about.
        let owner = file.owner().ok()?;
        let mut applicable = [
            0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb, 0xaa, 0xaa, 0, 0, 0, 0,
        ];
        applicable[12..16].copy_from_slice(&owner.user.to_be_bytes());
        let mut raw = vec![0_u8; 44 + 2 * 24];
        raw[0..4].copy_from_slice(&0x012c_c16d_u32.to_ne_bytes());
        raw[36..40].copy_from_slice(&2_u32.to_ne_bytes());
        for (index, (kind, rights)) in [(1_u32, 0x0000_0002_u32), (2, 0x0000_0400)]
            .into_iter()
            .enumerate()
        {
            let at = 44 + index * 24;
            raw[at..at + 16].copy_from_slice(&applicable);
            raw[at + 16..at + 20].copy_from_slice(&kind.to_ne_bytes());
            raw[at + 20..at + 24].copy_from_slice(&rights.to_ne_bytes());
        }
        kr_transfer::AccessControl::Apple(kr_transfer::AppleAcl::from_bytes(&raw).ok()?)
    };
    #[cfg(target_os = "linux")]
    let wanted = {
        // A POSIX list in the attribute's own layout: a version, then one eight-byte entry per
        // row, each a tag, the rights it allows and the user or group it names. Naming a user is
        // what makes the list say more than the mode bits do, and a list that names one carries a
        // mask beside it.
        let owner = file.owner().ok()?;
        let mut raw = Vec::with_capacity(4 + 5 * 8);
        raw.extend_from_slice(&2_u32.to_le_bytes());
        for (tag, rights, who) in [
            (0x0001_u16, 0x0006_u16, u32::MAX),
            (0x0002, 0x0004, owner.user),
            (0x0004, 0x0004, u32::MAX),
            (0x0010, 0x0004, u32::MAX),
            (0x0020, 0x0004, u32::MAX),
        ] {
            raw.extend_from_slice(&tag.to_le_bytes());
            raw.extend_from_slice(&rights.to_le_bytes());
            raw.extend_from_slice(&who.to_le_bytes());
        }
        kr_transfer::AccessControl::Posix(raw)
    };
    file.set_access_control(&wanted).ok()?;
    drop(file);
    let read = authority.open_read(name, ObjectPolicy::ReadableFile).ok()?;
    let carried = read.access_control().ok()?;
    carried.has_entries().then_some(carried)
}

/// Returns nothing: this platform keeps its access-control lists where this host cannot write one.
///
/// It stands in on the Unix hosts that are neither Apple's nor Linux. The case that calls it is a
/// Unix one, so nothing else needs it.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn give_an_access_control_list(
    _authority: &AuthorisedDirectory,
    _name: &RelativeName,
) -> Option<kr_transfer::AccessControl> {
    None
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
    if status.code() == Some(NOT_EXERCISED) {
        println!("not exercised: this namespace would not place a bind mount");
        return;
    }
    assert!(
        status.success(),
        "the reads inside the mount namespace did not hold: {status}"
    );
}

/// What the half inside the namespace exits with when it could not place a mount at all.
#[cfg(target_os = "linux")]
const NOT_EXERCISED: i32 = 42;

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

    // Both states, before anything races: the tree's own bytes when nothing covers the directory,
    // and a refusal while something does. A run that reached neither would prove nothing, so this
    // is asserted rather than hoped for.
    assert_eq!(
        read_through(&authority, &name),
        "inside",
        "the tree's own bytes when nothing covers its directory"
    );
    let onto = root.path().join("history");
    let from = root.path().join("elsewhere");
    if rustix::mount::mount_bind(&from, &onto).is_err() {
        std::process::exit(NOT_EXERCISED);
    }
    assert!(
        matches!(
            authority.open_read(&name, ObjectPolicy::ReadableFile),
            Err(Escape::CrossedMount { .. })
        ),
        "a read refuses while another tree is mounted over the directory it descends through"
    );
    rustix::mount::unmount(&onto, rustix::mount::UnmountFlags::DETACH)
        .expect("the mount comes off");
    assert_eq!(
        read_through(&authority, &name),
        "inside",
        "and the tree's own bytes again once it is off"
    );

    let stop = AtomicBool::new(false);
    let placed = AtomicUsize::new(0);

    std::thread::scope(|threads| {
        let mounter = threads.spawn(|| {
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
        assert!(
            mounts > 0,
            "the mount loop placed nothing, so the reads raced against nothing"
        );
        println!("{read} reads resolved, {refused} were refused, over {mounts} mounts");
    });
}

#[cfg(target_os = "macos")]
#[test]
fn a_macos_access_control_list_preserves_acl_level_flags() {
    let root = tempfile::tempdir().expect("a directory");
    let authority =
        AuthorisedDirectory::open_root(environment(), root.path()).expect("the authority opens");
    let name = RelativeName::parse("flagged.txt").expect("a name");
    std::fs::write(root.path().join("flagged.txt"), b"flagged\n").expect("a file");

    let file = authority.open_write(&name).expect("opens write");

    // Construct an AppleAcl carrying an entry and an ACL-level flag (e.g. ACL_FLAG_DEFER_INHERIT = 1).
    // Validate that setting and re-reading preserves both the entry and the flags independently.
    let mut raw = vec![0_u8; 68];
    // Magic: 0x012cc16d
    raw[0..4].copy_from_slice(&0x012c_c16d_u32.to_ne_bytes());
    // Entry count: 1 at offset 36
    raw[36..40].copy_from_slice(&1_u32.to_ne_bytes());
    // Flags: 1 (ACL_FLAG_DEFER_INHERIT) at offset 40
    raw[40..44].copy_from_slice(&1_u32.to_ne_bytes());
    // An ACE entry (24 bytes) at offset 44..68
    raw[44..68].copy_from_slice(&[
        0x01, 0x00, 0x00, 0x00, // tag type
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qualifier
        0x01, 0x00, 0x00, 0x00, // permissions
        0x00, 0x00, 0x00, 0x00, // flags
    ]);
    let acl = kr_transfer::AppleAcl::from_bytes(&raw).expect("valid flagged acl");
    assert_eq!(acl.entry_count(), 1);
    assert_eq!(acl.flags(), 1);
    assert!(acl.has_flags());

    file.set_access_control(&kr_transfer::AccessControl::Apple(acl.clone()))
        .expect("sets flagged acl");
    drop(file);

    let read_back = authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("opens read");
    assert!(read_back.carries_access_control());
    let read_acl = read_back.access_control().expect("reads acl");
    match read_acl {
        kr_transfer::AccessControl::Apple(read_apple) => {
            assert_eq!(read_apple.flags(), 1, "ACL-level flags are preserved");
            assert_eq!(read_apple.entry_count(), 1, "ACE entries are preserved");
            assert_eq!(read_apple, acl, "exact binary ACL matches");
        }
        _ => panic!("expected Apple ACL"),
    }

    // Second: A 44-byte fixture with zero entries and a nonzero ACL flag (e.g. ACL_FLAG_DEFER_INHERIT = 1).
    // Exercises preservation of ACL-level flags on empty entry lists without discarding as absence.
    let zero_name = RelativeName::parse("zero_entries_flagged.txt").expect("a name");
    std::fs::write(
        root.path().join("zero_entries_flagged.txt"),
        b"zero_entries\n",
    )
    .expect("a file");
    let file_zero = authority.open_write(&zero_name).expect("opens write");

    let mut raw_zero = vec![0_u8; 44];
    raw_zero[0..4].copy_from_slice(&0x012c_c16d_u32.to_ne_bytes());
    raw_zero[36..40].copy_from_slice(&0_u32.to_ne_bytes());
    raw_zero[40..44].copy_from_slice(&1_u32.to_ne_bytes());
    let acl_zero =
        kr_transfer::AppleAcl::from_bytes(&raw_zero).expect("valid 44-byte zero-entry flagged acl");
    assert_eq!(acl_zero.entry_count(), 0);
    assert_eq!(acl_zero.flags(), 1);
    assert!(!acl_zero.has_entries());
    assert!(acl_zero.has_flags());

    file_zero
        .set_access_control(&kr_transfer::AccessControl::Apple(acl_zero.clone()))
        .expect("setting a zero-entry flagged acl succeeds");
    drop(file_zero);

    // What the filesystem then keeps is its own decision, and on APFS it keeps nothing: a list of
    // no entries put on an inode deletes the inode's list, so reading the file back reports the
    // absence the platform made. That is an observation about the store, not about this host's
    // reading, which the case below settles on the representation itself.
    let read_zero = authority
        .open_read(&zero_name, ObjectPolicy::ReadableFile)
        .expect("opens read");
    assert_eq!(
        read_zero.access_control().expect("reads acl"),
        kr_transfer::AccessControl::None,
        "macOS filesystem clears ACL when entry count is zero"
    );
}

/// KR-REQ-14.29: a list of no entries that carries a flag of its own is still a list.
///
/// The filesystem will not hold such a list on an inode, so a case that wrote one and read it back
/// would prove what APFS does rather than what this host decides. This asks the decoding and the
/// classification directly instead: the representation the platform hands back is read, and what
/// the host makes of it is what a replacement consults before it takes a destination's protection
/// away.
#[cfg(target_os = "macos")]
#[test]
fn a_list_of_no_entries_that_carries_a_flag_is_protection_beyond_the_mode_bits() {
    /// The list's own flag that stops its entries being inherited by what is made below it.
    const KAUTH_ACL_NO_INHERIT: u32 = 1 << 17;

    let mut raw = vec![0_u8; 44];
    raw[0..4].copy_from_slice(&0x012c_c16d_u32.to_ne_bytes());
    raw[36..40].copy_from_slice(&0_u32.to_ne_bytes());
    raw[40..44].copy_from_slice(&KAUTH_ACL_NO_INHERIT.to_ne_bytes());

    let acl = kr_transfer::AppleAcl::from_bytes(&raw).expect("a 44-byte list of no entries");
    assert_eq!(acl.entry_count(), 0, "the list has no entries");
    assert_eq!(
        acl.flags(),
        KAUTH_ACL_NO_INHERIT,
        "the list's own flag survives the decoding"
    );
    assert!(!acl.has_entries());
    assert!(acl.has_flags());
    assert_eq!(
        acl.as_bytes(),
        raw.as_slice(),
        "the representation is carried across byte for byte"
    );

    let carried = kr_transfer::AccessControl::Apple(acl);
    assert!(
        carried.has_entries(),
        "a flag with no entries is protection a replacement would take away"
    );
    assert_ne!(
        carried,
        kr_transfer::AccessControl::None,
        "a list of no entries is not the absence of a list"
    );
}

/// KR-REQ-14.29: the user and the group a file belongs to are read through its own handle.
///
/// A list says what one named user and one named group may do and leaves the rest to the file's
/// own user and group, so a replacement that carried the list and not these would publish the same
/// protection to different people.
#[cfg(unix)]
#[test]
fn a_file_says_through_its_own_handle_which_user_and_group_it_belongs_to() {
    use std::os::unix::fs::MetadataExt as _;

    let root = tempfile::tempdir().expect("a directory");
    let authority =
        AuthorisedDirectory::open_root(environment(), root.path()).expect("the authority opens");
    let name = RelativeName::parse("owned.txt").expect("a name");
    let path = root.path().join("owned.txt");
    std::fs::write(&path, b"content\n").expect("a file");

    let file = authority
        .open_read(&name, ObjectPolicy::ReadableFile)
        .expect("it opens");
    let owner = file.owner().expect("reads the owner");
    let metadata = std::fs::metadata(&path).expect("reads the file");
    assert_eq!(owner.user, metadata.uid(), "the user is the file's own");
    assert_eq!(owner.group, metadata.gid(), "the group is the file's own");
    drop(file);

    // Giving a file to the user and group it already belongs to is what a replacement does when
    // nothing has to change, and it has to succeed rather than refuse.
    let writable = authority.open_write(&name).expect("it opens for writing");
    writable.set_owner(owner).expect("keeps the owner it has");
    assert_eq!(
        writable.owner().expect("reads the owner again"),
        owner,
        "the owner is unchanged"
    );

    // A host that is not the superuser cannot give a file to another user, and the refusal is what
    // makes an apply leave such a destination alone rather than publish over it.
    if owner.user != 0 {
        let stranger = kr_transfer::FileOwner {
            user: owner.user.wrapping_add(1),
            group: owner.group,
        };
        assert!(
            writable.set_owner(stranger).is_err(),
            "a file cannot be given to a user this host is not"
        );
        assert_eq!(
            writable.owner().expect("reads the owner once more"),
            owner,
            "a refused change leaves the file where it was"
        );
    }
}
