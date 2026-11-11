//! The anchored walk, shown on a Windows guest.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is
//! restored afterwards. Each walks a tree with a visitor that makes one small change, a mark in an
//! object's attributes, through the handle the walk gave it, and then looks at everything the walk
//! should not have reached: an object renamed out of the tree while the walk ran, a name given
//! another hard link, a name swapped for another object, a junction. None of those may carry the
//! mark, and the walk must say that it could not show where they were.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::cell::RefCell;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_APPEND_DATA, FILE_BASIC_INFO, FILE_EXECUTE, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FileBasicInfo,
    GetFileInformationByHandleEx, SetFileInformationByHandle,
};

use kr_boundary_windows::win::ffi::Handle;
use kr_boundary_windows::win::privilege;
use kr_boundary_windows::win::walk::{
    AnchorRefusal, Bounds, DELETE, DirHandle, Entry, Kind, LIST, Lost, RecordedDir, Verdict,
    VolumeRefusal, WalkError, testing as walking, walk,
};

use common::{Scratch, look_at, run};

const NOT_CONTENT_INDEXED: u32 = 0x2000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const BIG: Bounds = Bounds {
    objects: 10_000,
    depth: 64,
};

fn mark(handle: &Handle) {
    let mut info = FILE_BASIC_INFO::default();
    // SAFETY: the handle is open and the buffer is the structure the class fills.
    let read = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileBasicInfo,
            (&raw mut info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    assert_ne!(read, 0, "the attributes read");
    info.FileAttributes |= NOT_CONTENT_INDEXED;
    // SAFETY: the handle is open with the right to write attributes.
    let set = unsafe {
        SetFileInformationByHandle(
            handle.raw(),
            FileBasicInfo,
            (&raw const info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    assert_ne!(set, 0, "the mark is written");
}

fn marked(path: &Path) -> bool {
    std::fs::symlink_metadata(path).unwrap().file_attributes() & NOT_CONTENT_INDEXED != 0
}

/// What a visitor saw of each child: its name, and either what kind it was or why it was lost.
type Seen = RefCell<Vec<(String, Result<Kind, String>)>>;

/// Opens the child for the one small change and makes it unless it is a reparse point or has more
/// than one name, the rule the release will use for a write that is not keyed by a group.
fn mark_visitor<'a>(
    seen: &'a Seen,
) -> impl FnMut(&Entry<'_>) -> kr_boundary_windows::win::ffi::Result<Verdict> + 'a {
    move |entry| {
        let name = entry.child.display();
        // The right to write attributes alone would hold nothing, so a data right comes with it.
        match entry.open(FILE_WRITE_ATTRIBUTES | FILE_READ_DATA)? {
            Ok(opened) => {
                let kind = opened.kind();
                if kind != Kind::ReparsePoint && opened.links() == 1 {
                    mark(opened.handle());
                    seen.borrow_mut().push((name, Ok(kind)));
                } else {
                    seen.borrow_mut().push((
                        name,
                        Err(format!(
                            "not acted on: {kind:?}, {} link(s)",
                            opened.links()
                        )),
                    ));
                }
            }
            Err(lost) => seen.borrow_mut().push((name, Err(lost.to_string()))),
        }
        Ok(Verdict::Descend)
    }
}

fn anchor(path: &Path) -> DirHandle {
    DirHandle::open_anchor(path)
        .expect("the platform answers")
        .expect("the anchor is accepted")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_walk_goes_through_every_object_and_never_enters_a_junction_or_a_symbolic_link() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    std::fs::create_dir_all(tree.join("sub").join("deeper")).unwrap();
    std::fs::write(tree.join("one.txt"), b"1").unwrap();
    std::fs::write(tree.join("sub").join("two.txt"), b"2").unwrap();
    std::fs::write(tree.join("sub").join("deeper").join("three.txt"), b"3").unwrap();
    let outside = scratch.path("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim.txt"), b"keep").unwrap();
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/J",
            &tree.join("junction").display().to_string(),
            &outside.display().to_string(),
        ],
    );
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/D",
            &tree.join("symlink").display().to_string(),
            &outside.display().to_string(),
        ],
    );
    let before = look_at(&outside.join("victim.txt"));
    let start = anchor(&tree);
    let seen = Seen::default();
    let guard = privilege::enter().unwrap();
    let report = walk(&start, BIG, &mut mark_visitor(&seen)).expect("the walk runs");
    drop(guard);
    let seen = seen.take();
    let names: Vec<&str> = seen.iter().map(|(name, _)| name.as_str()).collect();
    for expected in [
        "one.txt",
        "sub",
        "two.txt",
        "deeper",
        "three.txt",
        "junction",
        "symlink",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} was visited: {names:?}"
        );
    }
    assert!(
        !names.contains(&"victim.txt"),
        "nothing behind a link was visited: {names:?}"
    );
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    for link in ["junction", "symlink"] {
        let result = seen
            .iter()
            .find(|(name, _)| name == link)
            .map(|(_, result)| result);
        assert_eq!(
            result,
            Some(&Err("not acted on: ReparsePoint, 1 link(s)".to_owned())),
            "{link} opens as itself, a reparse point, and not as the directory it points at"
        );
    }
    assert!(
        marked(&tree.join("sub").join("deeper").join("three.txt")),
        "a file three levels down is marked"
    );
    assert_eq!(
        look_at(&outside.join("victim.txt")),
        before,
        "the target of both links is as it was"
    );
    assert!(!marked(&outside), "and so is the directory they point at");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_descendant_renamed_out_of_the_tree_during_the_walk_is_reported_and_never_changed() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    let outside = scratch.path("outside");
    std::fs::create_dir_all(tree.join("c_dir")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(tree.join("a_trigger.txt"), b"t").unwrap();
    std::fs::write(tree.join("b_victim.txt"), b"v").unwrap();
    std::fs::write(tree.join("c_dir").join("inside.txt"), b"i").unwrap();
    let start = anchor(&tree);
    let seen = Seen::default();
    let mut inner = mark_visitor(&seen);
    let mut visitor = |entry: &Entry<'_>| {
        if entry.child.display() == "a_trigger.txt" {
            // After the listing and before the walk opens either, both go out of the tree.
            std::fs::rename(tree.join("b_victim.txt"), outside.join("b_victim.txt")).unwrap();
            std::fs::rename(tree.join("c_dir"), outside.join("c_dir")).unwrap();
        }
        inner(entry)
    };
    let guard = privilege::enter().unwrap();
    let report = walk(&start, BIG, &mut visitor).expect("the walk runs");
    drop(guard);
    let seen = seen.take();
    assert!(
        !marked(&outside.join("b_victim.txt")),
        "the file that left the tree was not changed"
    );
    assert!(
        !marked(&outside.join("c_dir")),
        "the directory that left the tree was not changed"
    );
    assert!(
        !marked(&outside.join("c_dir").join("inside.txt")),
        "nothing inside the directory that left was visited"
    );
    let victim = seen
        .iter()
        .find(|(name, _)| name == "b_victim.txt")
        .unwrap();
    assert!(
        victim.1.is_err(),
        "the walk says it lost the file: {victim:?}"
    );
    assert!(
        report
            .problems
            .iter()
            .any(|problem| problem.name == "c_dir" && problem.lost == Lost::MovedOut)
            || seen
                .iter()
                .any(|(name, result)| name == "c_dir" && result.is_err()),
        "the walk says it lost the directory: {:?} {seen:?}",
        report.problems
    );
    assert!(
        marked(&tree.join("a_trigger.txt")),
        "what stayed was visited"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_hard_link_made_during_the_walk_is_seen_in_the_link_count_and_the_file_is_not_changed() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    let outside = scratch.path("outside");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(tree.join("a_trigger.txt"), b"t").unwrap();
    std::fs::write(tree.join("b_file.txt"), b"f").unwrap();
    let start = anchor(&tree);
    let seen = Seen::default();
    let mut inner = mark_visitor(&seen);
    let mut visitor = |entry: &Entry<'_>| {
        if entry.child.display() == "a_trigger.txt" {
            std::fs::hard_link(tree.join("b_file.txt"), outside.join("link.txt")).unwrap();
        }
        inner(entry)
    };
    let guard = privilege::enter().unwrap();
    walk(&start, BIG, &mut visitor).expect("the walk runs");
    drop(guard);
    let seen = seen.take();
    let file = seen.iter().find(|(name, _)| name == "b_file.txt").unwrap();
    assert!(
        matches!(&file.1, Err(reason) if reason.contains("2 link(s)")),
        "the visitor saw two names and did not act: {file:?}"
    );
    assert!(
        !marked(&outside.join("link.txt")),
        "the object under the outside name is not changed"
    );
    assert!(
        !marked(&tree.join("b_file.txt")),
        "and neither is the name inside"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_name_swapped_for_another_object_during_the_walk_is_not_acted_on_by_the_old_identifier() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    let outside = scratch.path("outside");
    std::fs::create_dir_all(tree.join("c_dir")).unwrap();
    std::fs::create_dir_all(outside.join("target")).unwrap();
    std::fs::write(outside.join("target").join("t.txt"), b"keep").unwrap();
    std::fs::write(tree.join("a_trigger.txt"), b"t").unwrap();
    std::fs::write(tree.join("b_file.txt"), b"old").unwrap();
    std::fs::write(tree.join("c_dir").join("x.txt"), b"x").unwrap();
    let start = anchor(&tree);
    let seen = Seen::default();
    let mut inner = mark_visitor(&seen);
    let mut visitor = |entry: &Entry<'_>| {
        if entry.child.display() == "a_trigger.txt" {
            // The file's name now belongs to a new file; the directory's name to a junction.
            std::fs::remove_file(tree.join("b_file.txt")).unwrap();
            std::fs::write(tree.join("b_file.txt"), b"new").unwrap();
            std::fs::rename(tree.join("c_dir"), tree.join("c_dir_aside")).unwrap();
            run(
                "cmd.exe",
                &[
                    "/c",
                    "mklink",
                    "/J",
                    &tree.join("c_dir").display().to_string(),
                    &outside.join("target").display().to_string(),
                ],
            );
        }
        inner(entry)
    };
    let guard = privilege::enter().unwrap();
    walk(&start, BIG, &mut visitor).expect("the walk runs");
    drop(guard);
    let seen = seen.take();
    assert!(
        !marked(&tree.join("b_file.txt")),
        "the new file was not changed through the old identifier"
    );
    assert!(
        !marked(&outside.join("target").join("t.txt")),
        "nothing behind the junction was reached"
    );
    assert!(
        !marked(&tree.join("c_dir_aside").join("x.txt")),
        "the directory that moved aside was not entered"
    );
    let lost_file = seen.iter().find(|(name, _)| name == "b_file.txt");
    assert!(
        lost_file.is_none_or(|(_, result)| result.is_err()),
        "the old file is reported as lost, not acted on: {lost_file:?}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn every_directory_from_the_start_to_the_current_one_is_held_against_a_rename() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    std::fs::create_dir_all(tree.join("top").join("middle")).unwrap();
    std::fs::write(tree.join("top").join("middle").join("leaf.txt"), b"l").unwrap();
    let start = anchor(&tree);
    let refused = RefCell::new(Vec::new());
    let mut visitor = |entry: &Entry<'_>| {
        if entry.child.display() == "leaf.txt" {
            for (from, to) in [
                (tree.join("top").join("middle"), tree.join("top").join("m2")),
                (tree.join("top"), tree.join("t2")),
                (tree.clone(), scratch.path("tree2")),
            ] {
                refused
                    .borrow_mut()
                    .push((from.clone(), std::fs::rename(&from, &to).is_err()));
            }
        }
        Ok(Verdict::Descend)
    };
    let guard = privilege::enter().unwrap();
    walk(&start, BIG, &mut visitor).expect("the walk runs");
    drop(guard);
    for (from, was_refused) in refused.into_inner() {
        assert!(
            was_refused,
            "{} could not be renamed while a descendant was acted on",
            from.display()
        );
    }
    std::fs::rename(tree.join("top"), tree.join("t2")).expect("after the walk a rename works");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_tree_past_the_bounds_is_refused_not_walked_without_end() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    std::fs::create_dir_all(tree.join("a").join("b").join("c")).unwrap();
    for index in 0..8 {
        std::fs::write(tree.join(format!("f{index}.txt")), b"x").unwrap();
    }
    let start = anchor(&tree);
    let guard = privilege::enter().unwrap();
    let wide = walk(
        &start,
        Bounds {
            objects: 5,
            depth: 64,
        },
        &mut |_| Ok(Verdict::Descend),
    );
    assert!(matches!(wide, Err(WalkError::TooLarge(5))), "{wide:?}");
    let deep = walk(
        &start,
        Bounds {
            objects: 1000,
            depth: 2,
        },
        &mut |_| Ok(Verdict::Descend),
    );
    assert!(matches!(deep, Err(WalkError::TooDeep(2))), "{deep:?}");
    drop(guard);
}

/// Makes a small virtual disk with the file system given, mounted on a letter, and removes it
/// when dropped.
struct Disk {
    file: std::path::PathBuf,
}

impl Disk {
    fn new(
        scratch: &Scratch,
        file_system: &str,
        megabytes: u32,
        letter: char,
    ) -> Result<Disk, String> {
        let file = scratch.path(&format!("{file_system}.vhd"));
        let script = scratch.path(&format!("{file_system}.txt"));
        std::fs::write(
            &script,
            format!(
                "create vdisk file=\"{}\" maximum={megabytes} type=expandable\nselect vdisk file=\"{}\"\nattach vdisk\ncreate partition primary\nformat fs={file_system} quick\nassign letter={letter}\n",
                file.display(),
                file.display()
            ),
        )
        .unwrap();
        let out = std::process::Command::new("diskpart.exe")
            .arg("/s")
            .arg(&script)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let disk = Disk { file };
        if Path::new(&format!("{letter}:\\")).exists() {
            Ok(disk)
        } else {
            Err(text)
        }
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        let script = self.file.with_extension("detach.txt");
        let _ = std::fs::write(
            &script,
            format!(
                "select vdisk file=\"{}\"\ndetach vdisk\n",
                self.file.display()
            ),
        );
        let _ = std::process::Command::new("diskpart.exe")
            .arg("/s")
            .arg(&script)
            .output();
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn the_system_volume_is_accepted_and_every_other_kind_of_volume_is_refused_with_its_reason() {
    let scratch = Scratch::new();
    assert!(
        DirHandle::open_anchor(&scratch.dir).unwrap().is_ok(),
        "an NTFS fixed volume is accepted"
    );
    let tail = format!(
        r"localhost\C$\Users\Public\{}",
        scratch.dir.file_name().unwrap().to_string_lossy()
    );
    // The same share in each form that names one: the plain UNC path, and the two prefixes that
    // would otherwise be read as a local drive.
    for share in [
        format!(r"\\{tail}"),
        format!(r"\\?\UNC\{tail}"),
        format!(r"\\.\UNC\{tail}"),
        format!(r"\\?\unc\{tail}"),
    ] {
        match DirHandle::open_anchor(Path::new(&share)).expect("the platform answers") {
            Err(AnchorRefusal::Volume(VolumeRefusal::Remote)) => {}
            other => panic!("{share} is a share of this computer, a remote volume: {other:?}"),
        }
    }
    let fat =
        Disk::new(&scratch, "fat32", 100, 'R').expect("a FAT32 disk can be made on the guest");
    match DirHandle::open_anchor(Path::new("R:\\")).expect("the platform answers") {
        Err(AnchorRefusal::Volume(VolumeRefusal::NotNtfs(name))) => {
            assert_eq!(name, "FAT32");
        }
        other => panic!("a FAT32 volume is refused with its file system: {other:?}"),
    }
    drop(fat);
    match Disk::new(&scratch, "refs", 2048, 'S') {
        Ok(refs) => {
            match DirHandle::open_anchor(Path::new("S:\\")).expect("the platform answers") {
                Err(AnchorRefusal::Volume(VolumeRefusal::NotNtfs(name))) => {
                    assert_eq!(name, "ReFS")
                }
                other => panic!("a ReFS volume is refused with its file system: {other:?}"),
            }
            drop(refs);
        }
        Err(reason) => println!(
            "a ReFS volume could not be made on this guest, so that refusal was not shown: {reason}"
        ),
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_open_that_asks_for_no_delete_or_data_right_is_refused_and_one_that_does_holds_the_object() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("file.txt"), b"f").unwrap();
    let start = anchor(&tree);
    let listing = start.children(10).unwrap();
    let child = &listing.children[0];
    for attribute_or_security in [
        FILE_READ_ATTRIBUTES,
        FILE_WRITE_ATTRIBUTES,
        READ_CONTROL,
        WRITE_DAC,
        WRITE_OWNER,
        FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    ] {
        assert!(
            start.open_child(child, attribute_or_security).is_err(),
            "{attribute_or_security:#x} holds nothing and is refused"
        );
    }
    assert!(
        start
            .open_directory_named(&units("file.txt"), READ_CONTROL)
            .is_err(),
        "a named directory is held the same way"
    );
    // The platform fact the refusal rests on: an open for attributes alone is not held against a
    // rename, and one that takes part in share checks is.
    {
        let weak = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(tree.join("file.txt"))
            .unwrap();
        std::fs::rename(tree.join("file.txt"), tree.join("renamed.txt"))
            .expect("an attribute-only handle holds nothing");
        std::fs::rename(tree.join("renamed.txt"), tree.join("file.txt")).unwrap();
        drop(weak);
    }
    for holding in [
        DELETE,
        FILE_READ_DATA,
        FILE_WRITE_DATA,
        FILE_APPEND_DATA,
        FILE_EXECUTE,
    ] {
        let opened = start
            .open_child(child, holding)
            .expect("a holding right is accepted")
            .expect("the child opens");
        let renamed = std::fs::rename(tree.join("file.txt"), tree.join("renamed.txt"));
        assert_eq!(
            renamed.err().and_then(|error| error.raw_os_error()),
            Some(32),
            "{holding:#x}: the object is held against a rename while the handle is open"
        );
        drop(opened);
        std::fs::rename(tree.join("file.txt"), tree.join("renamed.txt"))
            .expect("after the handle closes a rename works");
        std::fs::rename(tree.join("renamed.txt"), tree.join("file.txt")).unwrap();
    }
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_directory_opened_by_a_recorded_key_compares_the_whole_key_on_the_handle_it_returns() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    let outside = scratch.path("outside");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(tree.join("file.txt"), b"f").unwrap();
    run(
        "cmd.exe",
        &[
            "/c",
            "mklink",
            "/J",
            &tree.join("junction").display().to_string(),
            &outside.display().to_string(),
        ],
    );
    let start = anchor(&tree);
    let listing = start.children(10).unwrap();
    let key_of = |name: &str| {
        listing
            .children
            .iter()
            .find(|child| child.display() == name)
            .unwrap()
            .key
    };
    let right = key_of("sub");
    let recorded = RecordedDir::open(start.handle(), &right)
        .expect("the platform answers")
        .expect("the recorded directory is accepted");
    assert_eq!(recorded.key(), right, "the handle carries the recorded key");
    let mut forged = right;
    forged.volume_serial ^= 1;
    match RecordedDir::open(start.handle(), &forged).expect("the platform answers") {
        Err(AnchorRefusal::OtherObject) => {}
        other => panic!("an identifier under another volume's serial is another object: {other:?}"),
    }
    match RecordedDir::open(start.handle(), &key_of("file.txt")).expect("the platform answers") {
        Err(AnchorRefusal::NotADirectory) => {}
        other => panic!("a file is not a directory: {other:?}"),
    }
    match RecordedDir::open(start.handle(), &key_of("junction")).expect("the platform answers") {
        Err(AnchorRefusal::ReparsePoint) => {}
        other => panic!("a junction is not entered: {other:?}"),
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_listing_stops_at_the_limit_it_is_given() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for index in 0..1000 {
        std::fs::write(tree.join(format!("f{index}.txt")), b"x").unwrap();
    }
    let start = anchor(&tree);
    let within = String::from_utf16_lossy(start.path());
    let recording = walking::record(&within);
    let five = start.children(5).unwrap();
    assert_eq!(five.children.len(), 5, "no more than the limit is returned");
    assert!(five.more, "and the listing says there are more");
    assert_eq!(
        recording.listing_calls(&within),
        1,
        "the listing stopped in the first read of the directory and did not read the rest to cut it"
    );
    let exact = start.children(1000).unwrap();
    assert_eq!((exact.children.len(), exact.more), (1000, false));
    assert!(
        recording.listing_calls(&within) >= 3,
        "the directory takes several reads to list whole, or the count above shows nothing"
    );
    let all = start.children(usize::MAX).unwrap();
    assert_eq!((all.children.len(), all.more), (1000, false));
    let before_none = recording.listing_calls(&within);
    let none = start.children(0).unwrap();
    assert_eq!((none.children.len(), none.more), (0, true));
    assert_eq!(
        recording.listing_calls(&within) - before_none,
        1,
        "a limit of nothing is answered by the first read"
    );
    let empty = scratch.path("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert!(anchor(&empty).children(0).unwrap().is_empty());
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn an_anchor_that_is_a_file_or_a_reparse_point_is_refused_and_so_is_a_named_directory_that_is_not_one()
 {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    let outside = scratch.path("outside");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(tree.join("file.txt"), b"f").unwrap();
    for (flag, name) in [("/J", "junction"), ("/D", "symlink")] {
        run(
            "cmd.exe",
            &[
                "/c",
                "mklink",
                flag,
                &tree.join(name).display().to_string(),
                &outside.display().to_string(),
            ],
        );
    }
    assert!(matches!(
        DirHandle::open_anchor(&tree.join("file.txt")).expect("the platform answers"),
        Err(AnchorRefusal::NotADirectory)
    ));
    for name in ["junction", "symlink"] {
        assert!(
            matches!(
                DirHandle::open_anchor(&tree.join(name)).expect("the platform answers"),
                Err(AnchorRefusal::ReparsePoint)
            ),
            "{name} is not an anchor"
        );
    }
    let start = anchor(&tree);
    for name in ["file.txt", "junction", "symlink"] {
        assert!(
            matches!(
                start.open_directory_named(&units(name), LIST).unwrap(),
                Err(Lost::IdentityChanged)
            ),
            "{name} is not held as a directory"
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn a_named_directory_must_carry_the_name_the_platform_stores_for_it() {
    let scratch = Scratch::new();
    let tree = scratch.path("tree");
    std::fs::create_dir_all(tree.join("Sub")).unwrap();
    let start = anchor(&tree);
    assert!(
        start
            .open_directory_named(&units("Sub"), LIST)
            .unwrap()
            .is_ok(),
        "the stored name opens"
    );
    assert!(
        matches!(
            start.open_directory_named(&units("sub"), LIST).unwrap(),
            Err(Lost::MovedOut)
        ),
        "a name that differs only by case reaches the directory, whose final path does not carry it, and is a lost proof"
    );
}
