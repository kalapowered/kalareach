//! `broker_admission`: which trees the broker admits, shown on a Windows guest.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is
//! restored afterwards, on NTFS. The first cases are about the slot: the broker takes the slot of a
//! tree by the identity of its directories, which the hold read from the handles it keeps, so every
//! spelling of one tree gives one slot, a tree inside a held tree is busy, and a race for one tree
//! has one winner.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use windows_sys::Win32::Storage::FileSystem::{
    GetShortPathNameW, GetVolumeNameForVolumeMountPointW,
};

use kr_boundary_windows::lifecycle::{LEFTOVER_WORDS, RULE_BUSY, RULE_LEFTOVER};
use kr_boundary_windows::slot::{Blocked, SlotTable};
use kr_boundary_windows::win::ffi::wide_path;
use kr_boundary_windows::win::hold::hold_tree;

use kr_boundary_windows::frame::Class;
use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::refusal::Refusal;
use kr_boundary_windows::win::admission::{
    ADMISSION_FAILED_WORDS, Admitted, LABEL_WORDS, LINK_WORDS, OPEN_WORDS, OWNER_WORDS,
    PERSON_LACKS_WORDS, Probes, RULE_LABEL, RULE_LINK, RULE_OPEN, RULE_OWNER, RULE_PERSON_LACKS,
    RULE_SIBLING, RULE_STALE, RULE_SYSTEM_LACKS, RULE_WRITER, SIBLING_WORDS, STALE_WORDS,
    SYSTEM_LACKS_WORDS, WRITER_WORDS, admit,
};
use kr_boundary_windows::win::ffi::Handle;
use kr_boundary_windows::win::rights::{Right, Sd, may, probe_token};
use kr_boundary_windows::win::sd::descriptor_from_text;

use common::people::{Boundary, Person, acting_as, prepare, runs_as_the_system};
use common::project::{Project, repository_at};
use common::{Scratch, file_described, hostile_file, privileged, run};

const SHARING_VIOLATION: i32 = 32;

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_threads_that_race_for_one_tree_give_one_slot_and_busy_to_the_rest() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    const THREADS: usize = 8;
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::new();
    let project = Project::make(&scratch, "race");
    let table = SlotTable::new();
    let path = project.root.to_str().unwrap().to_owned();
    for round in 0..10 {
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let client = person.as_client();
                let table = table.clone();
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                thread::spawn(move || {
                    // Every thread holds the tree first, as every invocation does, and then the
                    // threads ask for the slot together.
                    let hold = hold_tree(&path, &client).expect("the tree is held");
                    barrier.wait();
                    let slot = match table.try_acquire(&hold.identity) {
                        Ok(slot) => Some(slot),
                        Err(refusal) => {
                            assert_eq!(refusal.rule, RULE_BUSY, "round {round}");
                            None
                        }
                    };
                    (slot, hold)
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("a thread ends"))
            .collect();
        let winners = results.iter().filter(|(slot, _)| slot.is_some()).count();
        assert_eq!(winners, 1, "round {round}: one thread has the slot");
        for (slot, hold) in results {
            if let Some(slot) = slot {
                slot.free_after_clean_release();
            }
            drop(hold);
        }
        assert!(table.is_empty(), "round {round}: the slot is freed");
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_tree_inside_a_held_tree_and_the_tree_around_it_are_busy() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::new();
    let project = Project::make(&scratch, "nested");
    // A repository inside the tree, and a repository beside it under the same parent whose name
    // begins with the tree's (`root` and `root2`): it is not inside the tree.
    let inner_root = project.root.join("sub");
    repository_at(&inner_root);
    let beside_root = project.parent.join("root2");
    repository_at(&beside_root);
    let hold = |root: &Path| {
        hold_tree(root.to_str().unwrap(), &person.as_client()).expect("the tree is held")
    };
    let outer = hold(&project.root);
    let inner = hold(&inner_root);
    let beside = hold(&beside_root);
    assert!(
        inner.identity.chain.starts_with(&outer.identity.chain),
        "the chain of the inner tree begins with the outer tree's"
    );
    assert_eq!(inner.identity.chain.len(), outer.identity.chain.len() + 1);
    let table = SlotTable::new();
    // The outer tree holds the slot: the tree inside it is busy, the tree beside it is free.
    let outer_slot = table.try_acquire(&outer.identity).expect("the outer tree");
    let refusal = table
        .try_acquire(&inner.identity)
        .expect_err("the tree inside a held tree is refused");
    assert_eq!(refusal.rule, RULE_BUSY, "inside");
    let beside_slot = table
        .try_acquire(&beside.identity)
        .expect("a tree beside the held tree has a slot of its own");
    beside_slot.free_after_clean_release();
    outer_slot.free_after_clean_release();
    // The tree inside holds the slot: the tree around it is busy.
    let inner_slot = table.try_acquire(&inner.identity).expect("the inner tree");
    let refusal = table
        .try_acquire(&outer.identity)
        .expect_err("the tree around a held tree is refused");
    assert_eq!(refusal.rule, RULE_BUSY, "around");
    // A slot that stays closed keeps the tree's handles, and its reason refuses the tree around it.
    let inner_identity = inner.identity.clone();
    inner_slot.keep(Blocked::Leftover("hooks".to_owned()), Some(Box::new(inner)));
    let refusal = table
        .try_acquire(&outer.identity)
        .expect_err("the tree around a leftover is refused");
    assert_eq!(refusal.rule, RULE_LEFTOVER);
    assert_eq!(refusal.detail(), format!("{LEFTOVER_WORDS}: hooks"));
    let moved = inner_root.with_file_name("sub-moved");
    let renamed = fs::rename(&inner_root, &moved);
    assert_eq!(
        renamed.map_err(|failure| failure.raw_os_error()),
        Err(Some(SHARING_VIOLATION)),
        "the kept handles hold the tree where it is"
    );
    // Recovery frees the slot by the chain it recorded, and the handles go with it.
    table
        .reserve(&inner_identity, Blocked::Uncertain)
        .free_after_clean_release();
    assert!(table.is_empty());
    fs::rename(&inner_root, &moved).expect("the tree is no longer held");
    fs::rename(&moved, &inner_root).unwrap();
    drop(outer);
    drop(beside);
}

/// A drive letter that names a folder, removed when it is dropped.
struct Substituted(String);

impl Substituted {
    fn new(letter: &str, folder: &Path) -> Substituted {
        common::run("subst", &[letter, folder.to_str().unwrap()]);
        Substituted(letter.to_owned())
    }
}

impl Drop for Substituted {
    fn drop(&mut self) {
        // A drive that cannot be removed here is gone with the guest's checkpoint.
        std::process::Command::new("subst")
            .args([self.0.as_str(), "/d"])
            .output()
            .ok();
    }
}

fn from_wide(buffer: &[u16], length: u32) -> String {
    String::from_utf16_lossy(&buffer[..length as usize])
}

/// The short (8.3) spelling of a path, which the platform gives only where a name is longer than
/// eight characters.
fn short_form(path: &Path) -> String {
    let wide = wide_path(path);
    let mut buffer = vec![0_u16; 1024];
    // SAFETY: the path is NUL-terminated and the buffer length is passed.
    let length =
        unsafe { GetShortPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(length > 0, "the short form of {path:?} is read");
    from_wide(&buffer, length)
}

/// The spelling of a path that names the volume by its GUID.
fn volume_form(path: &Path) -> String {
    let text = path.to_str().unwrap();
    let root: Vec<u16> = format!("{}\\", &text[..2])
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut buffer = vec![0_u16; 64];
    // SAFETY: the root is NUL-terminated and the buffer length is passed.
    let read = unsafe {
        GetVolumeNameForVolumeMountPointW(root.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
    };
    assert_ne!(read, 0, "the volume's name is read");
    let end = buffer.iter().position(|unit| *unit == 0).unwrap();
    format!("{}{}", from_wide(&buffer, end as u32), &text[3..])
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_every_spelling_of_one_tree_gives_one_chain_and_one_slot() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::new();
    // A long name above the tree, so that the platform has a short one for it.
    let project = Project::make(&scratch, "a-folder-with-a-long-name");
    let plain: PathBuf = project.root.clone();
    let text = plain.to_str().unwrap().to_owned();
    let short = short_form(&plain);
    assert_ne!(
        short.to_lowercase(),
        text.to_lowercase(),
        "the guest's volume makes short names"
    );
    let substituted = Substituted::new("Z:", &project.base);
    let spellings = [
        ("a verbatim path", format!(r"\\?\{text}")),
        ("a short name", short),
        ("capital letters", text.to_uppercase()),
        ("the volume's name", volume_form(&plain)),
        ("a substituted drive", r"Z:\t\mid\parent\root".to_owned()),
        ("a trailing backslash", format!(r"{text}\")),
        ("a dot-dot", format!(r"{text}\..\root")),
    ];
    let reference = hold_tree(&text, &person.as_client()).expect("the plain path is held");
    let table = SlotTable::new();
    let slot = table
        .try_acquire(&reference.identity)
        .expect("the plain path's slot");
    let mut holds = Vec::new();
    for (what, spelling) in &spellings {
        let hold = hold_tree(spelling, &person.as_client())
            .unwrap_or_else(|refusal| panic!("{what}: the tree is held, not refused: {refusal}"));
        assert_eq!(hold.identity, reference.identity, "{what}: the same chain");
        assert_eq!(hold.path, reference.path, "{what}: the same final path");
        let refusal = table
            .try_acquire(&hold.identity)
            .expect_err("the slot is the same slot");
        assert_eq!(refusal.rule, RULE_BUSY, "{what}");
        holds.push(hold);
    }
    slot.free_after_clean_release();
    drop(holds);
    drop(reference);
    drop(substituted);
}

// ---------------------------------------------------------------------------------------------
// The rights of every object
// ---------------------------------------------------------------------------------------------

/// The two boundary accounts of a case, one for each class, and the manifest that records them.
struct Siblings {
    checkout: Boundary,
    connect: Boundary,
    manifest: Manifest,
}

impl Siblings {
    fn new() -> Siblings {
        let checkout = Boundary::new("krsca");
        let connect = Boundary::new("krscn");
        let mut manifest = Manifest::begin();
        manifest.record(
            ObjectKind::Account,
            "krb-checkout",
            Some(&checkout.sid.to_text().unwrap()),
        );
        manifest.record(
            ObjectKind::Account,
            "krb-connect",
            Some(&connect.sid.to_text().unwrap()),
        );
        Siblings {
            checkout,
            connect,
            manifest,
        }
    }

    /// The probe tokens, made now: a group that an account joined before this call is in its token.
    fn probes(&self) -> Probes {
        Probes::new(&self.manifest).expect("the probe tokens are made")
    }
}

/// Holds the project's tree and asks for its admission.
fn admit_project(
    person: &Person,
    siblings: &Siblings,
    project: &Project,
) -> Result<Admitted, Refusal> {
    let client = person.as_client();
    let hold = hold_tree(project.root.to_str().unwrap(), &client).expect("the tree is held");
    admit(&hold, &client, &siblings.probes())
}

/// Adds an entry for `who` (a name, or `*` and an identifier) to the object's list.
fn grant(path: &Path, who: &str, rights: &str) {
    run(
        "icacls",
        &[path.to_str().unwrap(), "/grant", &format!("{who}:{rights}")],
    );
}

const EVERYONE: &str = "*S-1-1-0";

/// A local group with one member, or none, made before the probe tokens are.
fn make_group(prefix: &str, member: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("{prefix}{}", &id[..8]);
    run("net", &["localgroup", &name, "/add"]);
    if !member.is_empty() {
        run("net", &["localgroup", &name, member, "/add"]);
    }
    name
}

fn display(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_shared_read_is_reported_and_a_shared_write_refuses_naming_the_object() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();

    // Nobody but the person, the system and the administrators has a right: no note, no refusal.
    let alone = Project::make_private(&scratch, "alone", &person.sid);
    let admitted = admit_project(&person, &siblings, &alone).expect("the private tree is admitted");
    assert!(admitted.notes.is_empty(), "no note: {:?}", admitted.notes);

    // Everyone may read: the read is reported by object and does not refuse.
    let shared = Project::make_private(&scratch, "shared", &person.sid);
    grant(&shared.root, EVERYONE, "(OI)(CI)R");
    let admitted = admit_project(&person, &siblings, &shared).expect("a shared read is admitted");
    let root = display(&shared.root);
    let config = display(&shared.git.join("config"));
    assert!(
        admitted.notes.contains(&format!("shared-read: {root}")),
        "the tree's root is reported: {:?}",
        admitted.notes
    );
    assert!(
        admitted.notes.contains(&format!("shared-read: {config}")),
        "the config is reported: {:?}",
        admitted.notes
    );

    // Everyone may modify, by an entry that every object takes: the tree is refused at its root and
    // the reply names the root and the right.
    let modify = Project::make_private(&scratch, "modify", &person.sid);
    grant(&modify.root, EVERYONE, "(OI)(CI)M");
    let refusal =
        admit_project(&person, &siblings, &modify).expect_err("a shared modify entry refuses");
    assert_eq!(refusal.rule, RULE_SIBLING);
    assert_eq!(
        refusal.detail(),
        format!(
            "{}, write data or add a file: {SIBLING_WORDS}",
            display(&modify.root)
        )
    );
    assert!(
        !refusal.detail().contains(ADMISSION_FAILED_WORDS),
        "a refusal for a right is not a failed check"
    );
}

const DIRECTORY_RIGHTS: [(&str, &str); 8] = [
    ("WD", "write data or add a file"),
    ("AD", "append data or add a folder"),
    ("WEA", "write extended attributes"),
    ("WA", "write attributes"),
    ("DC", "delete what is in the folder"),
    ("D", "delete"),
    ("WDAC", "change the access list"),
    ("WO", "change the owner"),
];

const FILE_RIGHTS: [(&str, &str); 7] = [
    ("WD", "write data or add a file"),
    ("AD", "append data or add a folder"),
    ("WEA", "write extended attributes"),
    ("WA", "write attributes"),
    ("D", "delete"),
    ("WDAC", "change the access list"),
    ("WO", "change the owner"),
];

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_each_write_right_alone_refuses_the_tree_naming_that_right() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    for (code, words) in DIRECTORY_RIGHTS {
        let project = Project::make_private(&scratch, &format!("d-{code}"), &person.sid);
        let folder = project.git.join("refs");
        grant(&folder, EVERYONE, &format!("({code})"));
        let refusal = admit_project(&person, &siblings, &project)
            .expect_err(&format!("a folder that anyone may {words} refuses"));
        assert_eq!(refusal.rule, RULE_SIBLING, "folder, {code}");
        assert_eq!(
            refusal.detail(),
            format!("{}, {words}: {SIBLING_WORDS}", display(&folder)),
            "folder, {code}"
        );
    }
    for (code, words) in FILE_RIGHTS {
        let project = Project::make_private(&scratch, &format!("f-{code}"), &person.sid);
        let file = project.git.join("HEAD");
        grant(&file, EVERYONE, &format!("({code})"));
        let refusal = admit_project(&person, &siblings, &project)
            .expect_err(&format!("a file that anyone may {words} refuses"));
        assert_eq!(refusal.rule, RULE_SIBLING, "file, {code}");
        assert_eq!(
            refusal.detail(),
            format!("{}, {words}: {SIBLING_WORDS}", display(&file)),
            "file, {code}"
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_the_probe_token_of_each_class_is_asked() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    // A group that only one boundary account belongs to gives a right to that account's sibling
    // alone. The groups are made before the probe tokens, which copy the account's groups.
    let of_checkout = make_group("krgc", &siblings.checkout.name);
    let of_connect = make_group("krgn", &siblings.connect.name);
    let of_nobody = make_group("krgx", "");
    for (label, group, refused) in [
        ("checkout", &of_checkout, true),
        ("connect", &of_connect, true),
        ("nobody", &of_nobody, false),
    ] {
        let project = Project::make_private(&scratch, label, &person.sid);
        let file = project.git.join("HEAD");
        grant(&file, group, "(M)");
        let outcome = admit_project(&person, &siblings, &project);
        if refused {
            let refusal = outcome.expect_err(&format!("a group of the {label} account refuses"));
            assert_eq!(refusal.rule, RULE_SIBLING, "{label}");
            assert_eq!(
                refusal.detail(),
                format!(
                    "{}, write data or add a file: {SIBLING_WORDS}",
                    display(&file)
                ),
                "{label}"
            );
        } else {
            outcome.expect("a group that no boundary account belongs to refuses nothing");
        }
    }
}

/// The write rights of a file, each with its mask, in the order the plan lists them.
const FILE_MASKS: [(Right, u32); 7] = [
    (Right::WriteData, 0x0002),
    (Right::AppendData, 0x0004),
    (Right::WriteEa, 0x0010),
    (Right::WriteAttributes, 0x0100),
    (Right::Delete, 0x0001_0000),
    (Right::WriteDac, 0x0004_0000),
    (Right::WriteOwner, 0x0008_0000),
];

/// Whether an open of the file with this one right succeeds for a thread that acts as the token.
fn opens_with(path: &Path, token: &Handle, mask: u32) -> bool {
    use std::os::windows::fs::OpenOptionsExt as _;
    acting_as(Some(token), || {
        fs::OpenOptions::new()
            .access_mode(mask)
            .share_mode(7)
            .open(path)
            .is_ok()
    })
}

/// The descriptor of a file as an access check reads it.
fn descriptor_of(path: &Path) -> Sd {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::IntoRawHandle as _;
    let file = fs::OpenOptions::new()
        .access_mode(0x0002_0000)
        .share_mode(7)
        .open(path)
        .expect("the file opens for its descriptor");
    let handle = Handle::new(file.into_raw_handle(), "a file").unwrap();
    Sd::of_handle(&handle).expect("the descriptor reads")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_deny_owner_rights_and_generic_entries_agree_with_a_real_open() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let siblings = Siblings::new();
    let scratch = Scratch::new();
    let probe = probe_token(&siblings.manifest, Class::Checkout).expect("the probe token is made");
    let owner = siblings.checkout.sid.to_text().unwrap();
    // Each descriptor is protected, and gives the system control so that the case can clean up.
    let table = [
        (
            "a deny entry before an allow entry",
            "O:SYD:P(D;;0x2;;;WD)(A;;FA;;;SY)(A;;FA;;;WD)".to_owned(),
            Some([false, true, true, true, true, true, true]),
        ),
        (
            "a generic write entry",
            "O:SYD:P(A;;FA;;;SY)(A;;GW;;;WD)".to_owned(),
            Some([true, true, true, true, false, false, false]),
        ),
        (
            "an owner rights entry on a file the account owns",
            format!("O:{owner}D:P(A;;FA;;;SY)(A;;0x2;;;OW)(A;;0x1;;;WD)"),
            None,
        ),
    ];
    for (index, (what, text, expected)) in table.iter().enumerate() {
        let path = scratch.path(&format!("object-{index}"));
        privileged(|| file_described(&path, &descriptor_from_text(text).unwrap(), b"x"));
        let descriptor = descriptor_of(&path);
        let mut answers = Vec::new();
        for (right, mask) in FILE_MASKS {
            let computed = may(&probe, &descriptor, right);
            let opened = opens_with(&path, &siblings.checkout.primary, mask);
            assert_eq!(
                computed, opened,
                "{what}: the access check and a real open agree on {right:?}"
            );
            answers.push(computed);
        }
        if let Some(expected) = expected {
            assert_eq!(&answers[..], &expected[..], "{what}: the answers");
        }
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_right_the_person_or_the_broker_lacks_refuses_early_naming_it() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let who = person.sid.to_text().unwrap();

    // The person may read it and may not change its list.
    let project = Project::make_private(&scratch, "person", &person.sid);
    let file = project.git.join("person-reads");
    let person_may_not = format!("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{who})");
    file_described(&file, &descriptor_from_text(&person_may_not).unwrap(), b"x");
    let refusal =
        admit_project(&person, &siblings, &project).expect_err("the person lacks a right");
    assert_eq!(refusal.rule, RULE_PERSON_LACKS);
    assert_eq!(
        refusal.detail(),
        format!(
            "{}, change the access list: {PERSON_LACKS_WORDS}",
            display(&file)
        )
    );

    // The broker may read it and may not change its list: the person owns it.
    let project = Project::make_private(&scratch, "broker", &person.sid);
    let file = project.git.join("broker-reads");
    let broker_may_not = format!("O:{who}D:P(A;;FR;;;SY)(A;;FA;;;{who})");
    privileged(|| file_described(&file, &descriptor_from_text(&broker_may_not).unwrap(), b"x"));
    let refusal =
        admit_project(&person, &siblings, &project).expect_err("the broker lacks a right");
    assert_eq!(refusal.rule, RULE_SYSTEM_LACKS);
    assert_eq!(
        refusal.detail(),
        format!(
            "{}, change the access list: {SYSTEM_LACKS_WORDS}",
            display(&file)
        )
    );

    // The broker cannot open it at all.
    let project = Project::make_private(&scratch, "closed", &person.sid);
    let file = project.git.join("closed");
    privileged(|| hostile_file(&file, &person.sid, b"x"));
    let refusal =
        admit_project(&person, &siblings, &project).expect_err("the broker cannot open it");
    assert_eq!(refusal.rule, RULE_OPEN);
    assert_eq!(
        refusal.detail(),
        format!("{}: {OPEN_WORDS}", display(&file))
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_right_on_an_ancestor_refuses_only_when_it_deletes_or_changes_the_list() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();

    // The right to add to a folder above the tree is not refused.
    let project = Project::make_private(&scratch, "adds", &person.sid);
    grant(&project.mid, EVERYONE, "(WD,AD)");
    admit_project(&person, &siblings, &project)
        .expect("the right to add above the tree is admitted");

    // Each of the rights that delete or change the list is refused, naming the folder.
    for (label, folder, code, words) in [
        ("children", "mid", "DC", "delete what is in the folder"),
        ("itself", "parent", "D", "delete"),
        ("list", "top", "WDAC", "change the access list"),
        ("owner", "base", "WO", "change the owner"),
    ] {
        let project = Project::make_private(&scratch, label, &person.sid);
        let above = match folder {
            "mid" => project.mid.clone(),
            "parent" => project.parent.clone(),
            "top" => project.top.clone(),
            _ => project.base.clone(),
        };
        grant(&above, EVERYONE, &format!("({code})"));
        let refusal = admit_project(&person, &siblings, &project)
            .expect_err(&format!("a right to {words} on {folder} refuses"));
        assert_eq!(refusal.rule, RULE_SIBLING, "{label}");
        assert_eq!(
            refusal.detail(),
            format!("{}, {words}: {SIBLING_WORDS}", display(&above)),
            "{label}"
        );
    }

    // A link inside the tree is refused by name; the broker does not follow it.
    let project = Project::make_private(&scratch, "link", &person.sid);
    let link = project.root.join("link");
    run(
        "cmd",
        &[
            "/c",
            "mklink",
            "/J",
            link.to_str().unwrap(),
            project.top.to_str().unwrap(),
        ],
    );
    let refusal = admit_project(&person, &siblings, &project).expect_err("a link refuses");
    assert_eq!(refusal.rule, RULE_LINK);
    assert_eq!(
        refusal.detail(),
        format!("{}: {LINK_WORDS}", display(&link))
    );
}

// ---------------------------------------------------------------------------------------------
// The Git folder's writers, the groups of invocations that did not finish, and labels
// ---------------------------------------------------------------------------------------------

/// The first part of the identifier of an invocation's group, written out here so that a change
/// of the crate's number is seen: the number 0x4B524247.
const GROUP_FIRST: u32 = 1_263_682_119;

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_another_account_that_can_write_in_the_git_folder_refuses_the_tree() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let other = Person::new("krsec");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let other_sid = other.sid.to_text().unwrap();

    // An explicit right to write, given to a second ordinary account on an object of the Git
    // folder: no probe token stands for that account, so the entry itself is read.
    let project = Project::make_private(&scratch, "writes", &person.sid);
    let head = project.git.join("HEAD");
    grant(&head, &other.name, "(M)");
    let refusal = admit_project(&person, &siblings, &project).expect_err("a second writer refuses");
    assert_eq!(refusal.rule, RULE_WRITER);
    assert_eq!(
        refusal.detail(),
        format!("{WRITER_WORDS} {other_sid} on {}", display(&head))
    );

    // The same account may read it.
    let project = Project::make_private(&scratch, "reads", &person.sid);
    grant(&project.git.join("HEAD"), &other.name, "(R)");
    admit_project(&person, &siblings, &project).expect("a second account that reads is admitted");

    // The rule is the Git folder's: the same account may write a file of the working tree.
    let project = Project::make_private(&scratch, "work", &person.sid);
    let work = project.root.join("src.txt");
    fs::write(&work, b"x").unwrap();
    grant(&work, &other.name, "(M)");
    admit_project(&person, &siblings, &project)
        .expect("a second account that writes the working tree is admitted");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_an_owner_other_than_the_person_the_system_or_an_administrator_refuses_the_tree()
{
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let other = Person::new("krsec");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let who = person.sid.to_text().unwrap();
    let other_sid = other.sid.to_text().unwrap();
    // The list gives nobody else a right; the owner of an object may change its list.
    let owned_by_other = format!("O:{other_sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{who})");

    let project = Project::make_private(&scratch, "git", &person.sid);
    let file = project.git.join("owned");
    privileged(|| file_described(&file, &descriptor_from_text(&owned_by_other).unwrap(), b"x"));
    let refusal = admit_project(&person, &siblings, &project).expect_err("a second owner refuses");
    assert_eq!(refusal.rule, RULE_OWNER);
    assert_eq!(
        refusal.detail(),
        format!("{OWNER_WORDS} {other_sid} on {}", display(&file))
    );

    let project = Project::make_private(&scratch, "work", &person.sid);
    let file = project.root.join("owned.txt");
    privileged(|| file_described(&file, &descriptor_from_text(&owned_by_other).unwrap(), b"x"));
    admit_project(&person, &siblings, &project)
        .expect("a file of the working tree that another account owns is admitted");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_group_of_an_invocation_that_did_not_finish_refuses_the_tree() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let who = person.sid.to_text().unwrap();
    assert!(
        kr_boundary_windows::win::token::new_invocation_group()
            .to_text()
            .unwrap()
            .starts_with(&format!("S-1-9-{GROUP_FIRST}-")),
        "a new group has the form that admission names"
    );
    let with_entry =
        |sid: &str| format!("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{who})(A;;0x1301bf;;;{sid})");

    // A group of an invocation that did not finish, on a file of the working tree and on one of
    // the Git folder: refused, naming the object.
    for (label, git) in [("work", false), ("git", true)] {
        let project = Project::make_private(&scratch, label, &person.sid);
        let file = if git {
            project.git.join("stale")
        } else {
            project.root.join("stale.txt")
        };
        let stale = with_entry(&format!("S-1-9-{GROUP_FIRST}-11-22-33"));
        file_described(&file, &descriptor_from_text(&stale).unwrap(), b"x");
        let refusal =
            admit_project(&person, &siblings, &project).expect_err("a stale group refuses");
        assert_eq!(refusal.rule, RULE_STALE, "{label}");
        assert_eq!(
            refusal.detail(),
            format!("{STALE_WORDS} on {}", display(&file)),
            "{label}"
        );
    }

    // Other identifiers of the same authority, or of the same first part with fewer parts, are not
    // the crate's groups: on a file of the working tree they refuse nothing.
    for (label, sid) in [
        ("other-first", "S-1-9-1-11-22-33".to_owned()),
        ("short", format!("S-1-9-{GROUP_FIRST}-11-22")),
    ] {
        let project = Project::make_private(&scratch, label, &person.sid);
        let file = project.root.join("other.txt");
        file_described(
            &file,
            &descriptor_from_text(&with_entry(&sid)).unwrap(),
            b"x",
        );
        admit_project(&person, &siblings, &project)
            .unwrap_or_else(|refusal| panic!("{label}: {sid} is not a group of ours: {refusal}"));
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_mandatory_label_on_any_object_refuses_the_tree() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    for (label, git) in [("work", false), ("git", true)] {
        let project = Project::make_private(&scratch, label, &person.sid);
        let file = if git {
            project.git.join("HEAD")
        } else {
            let file = project.root.join("low.txt");
            fs::write(&file, b"x").unwrap();
            file
        };
        run(
            "icacls",
            &[file.to_str().unwrap(), "/setintegritylevel", "L"],
        );
        let refusal = admit_project(&person, &siblings, &project).expect_err("a label refuses");
        assert_eq!(refusal.rule, RULE_LABEL, "{label}");
        assert_eq!(
            refusal.detail(),
            format!("{LABEL_WORDS} on {}", display(&file)),
            "{label}"
        );
    }
}
