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
use std::time::Duration;

use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

use kr_boundary_windows::lifecycle::{LEFTOVER_WORDS, RULE_BUSY, RULE_LEFTOVER};
use kr_boundary_windows::slot::{Blocked, SlotTable};
use kr_boundary_windows::win::ffi::wide_path;
use kr_boundary_windows::win::hold::{FOLDER_FORM_WORDS, RULE_FOLDER_FORM, TreeHold, hold_tree};

use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::frame::Class;
use kr_boundary_windows::refusal::Refusal;
use kr_boundary_windows::win::admission::{
    ADMISSION_FAILED_WORDS, Admitted, CASE_SENSITIVE_WORDS, CLOUD_WORDS, DRIVE_WORDS,
    ENCRYPTED_WORDS, Expected, HARD_LINK_WORDS, LABEL_WORDS, LIMITS, LINK_WORDS, Limits,
    NESTED_WORDS, Names, OPEN_WORDS, OWNER_WORDS, PERSON_LACKS_WORDS, PROFILE_WORDS,
    RECHECK_LINKS_WORDS, RULE_CASE_SENSITIVE, RULE_CLOUD, RULE_DRIVE, RULE_ENCRYPTED,
    RULE_HARD_LINK, RULE_LABEL, RULE_LINK, RULE_NESTED, RULE_OPEN, RULE_OWNER, RULE_PERSON_LACKS,
    RULE_PROFILE, RULE_SIBLING, RULE_STALE, RULE_SYSTEM_LACKS, RULE_TOO_LARGE, RULE_WRITER,
    Recheck, SIBLING_WORDS, STALE_WORDS, SYSTEM_LACKS_WORDS, TOO_LARGE_WORDS, WRITER_WORDS, admit,
    admit_within, attributes_refusal, is_cloud_tag, recheck, recheck_refusal, reparse_refusal,
};
use kr_boundary_windows::win::ffi::Handle;
use kr_boundary_windows::win::rights::{Right, Sd, may, probe_token};
use kr_boundary_windows::win::sd::descriptor_from_text;
use kr_boundary_windows::win::walk::INSPECT;

use common::disk::Disk;
use common::people::{Person, Siblings, acting_as, prepare, runs_as_the_system};
use common::project::{Project, repository_at};
use common::{Scratch, file_described, hostile_file, privileged, run, smb_connections};

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
    // The forms that the broker refuses (the volume's name, a substituted drive, a dot-dot) are
    // refused in `broker_text`; these are the spellings of a path on a local drive.
    let spellings = [
        ("a verbatim path", format!(r"\\?\{text}")),
        ("a short name", short),
        ("capital letters", text.to_uppercase()),
        ("a trailing backslash", format!(r"{text}\")),
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
}

// ---------------------------------------------------------------------------------------------
// The rights of every object
// ---------------------------------------------------------------------------------------------

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
            // The writer rule refuses it: no principal besides the person, the system and the
            // administrators may write under the Git folder, because a group's members can change
            // after the admission, so who belongs to the group today does not decide.
            let refusal =
                outcome.expect_err("a group that no boundary account belongs to is a writer");
            assert_eq!(refusal.rule, RULE_WRITER, "{label}");
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
fn broker_admission_an_inherit_only_entry_for_the_creators_group_that_writes_refuses_the_tree() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();

    // An empty folder of the Git folder with a template for the creator's primary group: a ref made
    // in it later inherits the right for that group, which the boundary token neither sets nor
    // checks, so another boundary account of the group could write the ref. The entry does not
    // apply to the folder itself, so no access check on the folder shows it.
    let project = Project::make_private(&scratch, "group", &person.sid);
    let heads = project.git.join("refs").join("heads");
    fs::create_dir_all(&heads).unwrap();
    grant(&heads, "*S-1-3-1", "(OI)(IO)(WD)");
    let refusal = admit_project(&person, &siblings, &project)
        .expect_err("a template that gives the creator's group the right to write refuses");
    assert_eq!(refusal.rule, RULE_WRITER);
    assert_eq!(
        refusal.detail(),
        format!("{WRITER_WORDS} S-1-3-1 on {}", display(&heads))
    );

    // The template for the creator itself is exempt: an object made later is owned by the account
    // that makes it, which is the invocation's own.
    let project = Project::make_private(&scratch, "owner", &person.sid);
    let heads = project.git.join("refs").join("heads");
    fs::create_dir_all(&heads).unwrap();
    grant(&heads, "*S-1-3-0", "(OI)(IO)(WD)");
    admit_project(&person, &siblings, &project)
        .expect("a template for the creator owner is admitted");

    // A template for the creator's group that does not write is not a writer.
    let project = Project::make_private(&scratch, "reads", &person.sid);
    let heads = project.git.join("refs").join("heads");
    fs::create_dir_all(&heads).unwrap();
    grant(&heads, "*S-1-3-1", "(OI)(IO)(RD)");
    admit_project(&person, &siblings, &project)
        .expect("a template for the creator's group that only reads is admitted");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_an_object_entry_that_gives_writing_names_its_own_identifier_and_refuses_the_tree()
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
    // The person owns the object and keeps every right; `entry` is the one entry under test, added
    // to a list that the platform's own text form writes.
    let described =
        |entry: &str| format!("O:{who}G:BAD:P(A;;FA;;;{who})(A;;FA;;;SY)(A;;FA;;;BA){entry}");
    let make = |name: &str, entry: &str| {
        let project = Project::make_private(&scratch, name, &person.sid);
        let file = project.git.join("entry");
        let descriptor = descriptor_from_text(&described(entry)).unwrap();
        privileged(|| file_described(&file, &descriptor, b"x"));
        (project, file)
    };

    // An allow entry for an object type, with no object type named, gives the right to write like a
    // plain entry does: its identifier is the one the entry names, not the bytes that a plain entry
    // would have at that place.
    let (project, file) = make("plain", &format!("(OA;;0x2;;;{other_sid})"));
    let refusal = admit_project(&person, &siblings, &project)
        .expect_err("an object entry that gives writing to a second account refuses");
    assert_eq!(refusal.rule, RULE_WRITER);
    assert_eq!(
        refusal.detail(),
        format!("{WRITER_WORDS} {other_sid} on {}", display(&file))
    );

    // The same with an object type and an inherited object type named: the identifier lies after both.
    let guid = "bf967aba-0de6-11d0-a285-00aa00304900";
    let (project, file) = make("types", &format!("(OA;;0x2;{guid};{guid};{other_sid})"));
    let refusal = admit_project(&person, &siblings, &project)
        .expect_err("an object entry with two object types that gives writing refuses");
    assert_eq!(refusal.rule, RULE_WRITER);
    assert_eq!(
        refusal.detail(),
        format!("{WRITER_WORDS} {other_sid} on {}", display(&file))
    );

    // An allow entry with a condition is read by its type too.
    let (project, file) = make(
        "callback",
        &format!("(XA;;0x2;;;{other_sid};(Member_of {{SID(BA)}}))"),
    );
    let refusal = admit_project(&person, &siblings, &project)
        .expect_err("a conditional entry that gives writing refuses");
    assert_eq!(refusal.rule, RULE_WRITER);
    assert_eq!(
        refusal.detail(),
        format!("{WRITER_WORDS} {other_sid} on {}", display(&file))
    );

    // A deny entry for the second account gives nothing.
    let (project, _) = make("deny", &format!("(OD;;0x2;;;{other_sid})"));
    admit_project(&person, &siblings, &project)
        .expect("an object entry that denies writing is admitted");

    // An object entry for the person is an entry of a writer the rule allows.
    let (project, _) = make("person", &format!("(OA;;0x2;;;{who})"));
    admit_project(&person, &siblings, &project)
        .expect("an object entry that gives the person the right to write is admitted");
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

// ---------------------------------------------------------------------------------------------
// Where the product runs, and the bounds of the walk
// ---------------------------------------------------------------------------------------------

fn held(person: &Person, path: &Path) -> TreeHold {
    hold_tree(path.to_str().unwrap(), &person.as_client()).expect("the tree is held")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_volume_that_is_not_local_ntfs_is_refused_with_its_reason() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::on_drive();
    let client = person.as_client();

    // A share of this computer is refused for its form, before anything is opened: the computer
    // makes no SMB connection for it (`broker_text` holds the other forms and the observables).
    let project = Project::make_private(&scratch, "share", &person.sid);
    let share = format!(
        r"\\localhost\C$\{}",
        project.root.strip_prefix(r"C:\").unwrap().display()
    );
    let connections = smb_connections();
    let refusal = hold_tree(&share, &client).expect_err("a share is refused");
    assert_eq!(refusal.rule, RULE_FOLDER_FORM);
    assert_eq!(refusal.detail(), FOLDER_FORM_WORDS);
    assert_eq!(
        smb_connections(),
        connections,
        "the share was opened: the computer made an SMB connection"
    );

    // A volume of another file system is refused with the file system's name.
    let fat = Disk::new(&scratch, "fat32", 100, 'R').expect("a FAT32 disk can be made");
    fs::create_dir(r"R:\p").unwrap();
    let refusal = hold_tree(r"R:\p", &client).expect_err("a FAT32 volume is refused");
    assert_eq!(
        refusal.detail(),
        "the volume uses FAT32, and only NTFS volumes are supported"
    );
    drop(fat);

    // ReFS, which a Dev Drive is, when the guest can make a volume of it.
    match Disk::new(&scratch, "refs", 2048, 'S') {
        Ok(refs) => {
            fs::create_dir(r"S:\p").unwrap();
            let refusal = hold_tree(r"S:\p", &client).expect_err("a ReFS volume is refused");
            assert_eq!(
                refusal.detail(),
                "the volume uses ReFS, and only NTFS volumes are supported"
            );
            drop(refs);
        }
        Err(reason) => {
            println!("NOT SHOWN: a ReFS volume could not be made on this guest: {reason}")
        }
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_profile_folder_and_a_drive_root_are_refused_as_the_tree_root() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let who = person.sid.to_text().unwrap();

    // A folder directly in the folder of the users' profiles.
    let profile = PathBuf::from(format!(r"C:\Users\krprof-{}", &who[who.len() - 8..]));
    fs::create_dir_all(&profile).unwrap();
    grant(&profile, &format!("*{who}"), "(OI)(CI)F");
    repository_at(&profile);
    let hold = held(&person, &profile);
    let refusal = admit(&hold, &person.as_client(), &siblings.probes())
        .expect_err("a profile folder is refused");
    assert_eq!(refusal.rule, RULE_PROFILE);
    assert_eq!(
        refusal.detail(),
        format!("{}: {PROFILE_WORDS}", display(&profile))
    );
    drop(hold);

    // The root of a drive.
    let disk = Disk::new(&scratch, "ntfs", 100, 'T').expect("an NTFS disk can be made");
    grant(Path::new(r"T:\"), &format!("*{who}"), "(OI)(CI)F");
    repository_at(Path::new(r"T:\"));
    let hold = held(&person, Path::new(r"T:\"));
    let refusal = admit(&hold, &person.as_client(), &siblings.probes())
        .expect_err("a drive's root is refused");
    assert_eq!(refusal.rule, RULE_DRIVE);
    assert_eq!(refusal.detail(), format!(r"T:\: {DRIVE_WORDS}"));
    drop(hold);
    drop(disk);
}

/// Makes a folder case-sensitive; the folder must be empty.
fn make_case_sensitive(folder: &Path) {
    run(
        "fsutil.exe",
        &[
            "file",
            "setCaseSensitiveInfo",
            folder.to_str().unwrap(),
            "enable",
        ],
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_case_sensitive_folder_and_a_repository_inside_the_project_are_refused() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();

    // A folder inside the tree.
    let project = Project::make_private(&scratch, "inside", &person.sid);
    let folder = project.root.join("src");
    fs::create_dir(&folder).unwrap();
    make_case_sensitive(&folder);
    let refusal = admit_project(&person, &siblings, &project).expect_err("the folder refuses");
    assert_eq!(refusal.rule, RULE_CASE_SENSITIVE);
    assert_eq!(
        refusal.detail(),
        format!("{}: {CASE_SENSITIVE_WORDS}", display(&folder))
    );

    // A folder above the tree: the empty folder is made case-sensitive before the tree is made in it.
    let base = scratch.path("above");
    let parent = base.join("parent");
    fs::create_dir_all(&parent).unwrap();
    grant(
        &base,
        &format!("*{}", person.sid.to_text().unwrap()),
        "(OI)(CI)F",
    );
    make_case_sensitive(&parent);
    let root = parent.join("root");
    repository_at(&root);
    let hold = held(&person, &root);
    let refusal = admit(&hold, &person.as_client(), &siblings.probes())
        .expect_err("the folder above refuses");
    assert_eq!(refusal.rule, RULE_CASE_SENSITIVE);
    assert_eq!(
        refusal.detail(),
        format!("{}: {CASE_SENSITIVE_WORDS}", display(&parent))
    );
    drop(hold);

    // A repository inside the project, as a folder and as the file that a submodule leaves.
    for (label, as_folder) in [("nested-folder", true), ("nested-file", false)] {
        let project = Project::make_private(&scratch, label, &person.sid);
        let inner = project.root.join("sub");
        fs::create_dir(&inner).unwrap();
        let marker = inner.join(".git");
        if as_folder {
            repository_at(&inner);
        } else {
            fs::write(&marker, "gitdir: ../.git/modules/sub\n").unwrap();
        }
        let refusal =
            admit_project(&person, &siblings, &project).expect_err("a nested .git refuses");
        assert_eq!(refusal.rule, RULE_NESTED, "{label}");
        assert_eq!(
            refusal.detail(),
            format!("{}: {NESTED_WORDS}", display(&marker)),
            "{label}"
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_an_encrypted_object_and_a_cloud_placeholder_are_refused_naming_the_cause() {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{EncryptFileW, FILE_ATTRIBUTE_ENCRYPTED};
    use windows_sys::Win32::System::IO::DeviceIoControl;
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();

    // What the attributes and the tag say, whatever a guest can make.
    for tag in [0x9000_001A, 0x9000_101A, 0x9000_F01A] {
        assert!(is_cloud_tag(tag), "{tag:#x} is a cloud tag");
        assert_eq!(reparse_refusal(tag, "P").rule, RULE_CLOUD, "{tag:#x}");
    }
    for tag in [0xA000_0003, 0xA000_000C, 0x8000_0017] {
        assert!(!is_cloud_tag(tag), "{tag:#x} is not a cloud tag");
        assert_eq!(reparse_refusal(tag, "P").rule, RULE_LINK, "{tag:#x}");
    }
    assert_eq!(
        attributes_refusal(FILE_ATTRIBUTE_ENCRYPTED, "P").map(|refusal| refusal.rule),
        Some(RULE_ENCRYPTED)
    );
    assert!(attributes_refusal(0x20, "P").is_none());

    // A placeholder of a cloud-synchronised folder, when the guest takes the tag.
    let project = Project::make_private(&scratch, "cloud", &person.sid);
    let placeholder = project.root.join("placeholder.txt");
    fs::write(&placeholder, b"").unwrap();
    let mut header = [0_u8; 8];
    header[..4].copy_from_slice(&0x9000_001A_u32.to_le_bytes());
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;
        fs::OpenOptions::new()
            .write(true)
            .custom_flags(0x0020_0000)
            .open(&placeholder)
            .unwrap()
    };
    let mut returned = 0_u32;
    // SAFETY: the file is open for writing; the buffer is 8 bytes and its length is passed.
    let set = unsafe {
        use std::os::windows::io::AsRawHandle as _;
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_00A4,
            header.as_ptr().cast(),
            8,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    // The error is read at the call that failed, before anything else can change it.
    let set_error = std::io::Error::last_os_error();
    drop(file);
    if set == 0 {
        println!("NOT SHOWN: the guest does not take a cloud tag on a file: {set_error}");
    } else {
        let refusal =
            admit_project(&person, &siblings, &project).expect_err("a placeholder refuses");
        assert_eq!(refusal.rule, RULE_CLOUD);
        assert_eq!(
            refusal.detail(),
            format!("{}: {CLOUD_WORDS}", display(&placeholder))
        );
    }

    // A file that the person encrypted, when the guest lets the account encrypt.
    let project = Project::make_private(&scratch, "encrypted", &person.sid);
    let secret = project.root.join("secret.txt");
    fs::write(&secret, b"x").unwrap();
    let wide: Vec<u16> = secret.as_os_str().encode_wide().chain([0]).collect();
    // The error is read inside the account's turn, at the call that failed: ending the turn
    // changes the thread's last error.
    let (encrypted, encrypt_error) = acting_as(Some(&person.primary), || {
        // SAFETY: the path is NUL-terminated and lives through the call.
        let done = unsafe { EncryptFileW(wide.as_ptr()) };
        (done, std::io::Error::last_os_error())
    });
    if encrypted == 0 {
        println!("NOT SHOWN: the account cannot encrypt a file on this guest: {encrypt_error}");
    } else {
        let refusal =
            admit_project(&person, &siblings, &project).expect_err("an encrypted file refuses");
        assert_eq!(refusal.rule, RULE_ENCRYPTED);
        assert_eq!(
            refusal.detail(),
            format!("{}: {ENCRYPTED_WORDS}", display(&secret))
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_tree_beyond_the_bounds_of_the_walk_is_refused_as_too_large() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    assert_eq!(
        (LIMITS.objects, LIMITS.depth, LIMITS.time),
        (100_000, 64, Duration::from_secs(60)),
        "the bounds of the plan"
    );
    // The tree has five objects: .git, config, HEAD, objects and refs, at most two levels deep.
    let project = Project::make_private(&scratch, "small", &person.sid);
    let client = person.as_client();
    let hold = held(&person, &project.root);
    let probes = siblings.probes();
    let within = |objects, depth, time| {
        admit_within(
            &hold,
            &client,
            &probes,
            Limits {
                objects,
                depth,
                time,
            },
        )
    };
    let minute = Duration::from_secs(60);
    within(5, 3, minute).expect("five objects, three levels and a minute are enough");
    for (what, outcome) in [
        ("four objects", within(4, 3, minute)),
        ("two levels", within(5, 2, minute)),
        ("no time", within(5, 3, Duration::ZERO)),
    ] {
        let refusal = outcome.expect_err(&format!("{what} are too few"));
        assert_eq!(refusal.rule, RULE_TOO_LARGE, "{what}");
        assert_eq!(refusal.detail(), TOO_LARGE_WORDS, "{what}");
    }
}

// ---------------------------------------------------------------------------------------------
// The names of a file, and the recheck before a write
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_file_with_more_than_one_name_is_refused() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "names", &person.sid);
    let file = project.root.join("a.txt");
    fs::write(&file, b"x").unwrap();
    // The second name is outside the tree, where a grant of the tree would not reach.
    fs::hard_link(&file, scratch.path("outside.txt")).unwrap();
    let refusal = admit_project(&person, &siblings, &project).expect_err("a second name refuses");
    assert_eq!(refusal.rule, RULE_HARD_LINK);
    assert_eq!(
        refusal.detail(),
        format!("{}: {HARD_LINK_WORDS}", display(&file))
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_admission_a_name_made_after_admission_a_changed_identity_and_a_moved_object_are_seen() {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::IntoRawHandle as _;
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "recheck", &person.sid);
    let file = project.root.join("f.txt");
    fs::write(&file, b"x").unwrap();
    let moving = project.root.join("g.txt");
    fs::write(&moving, b"x").unwrap();
    let hold = held(&person, &project.root);
    let root = hold.chain.last().unwrap();
    let children = root.children().unwrap();
    let listed = |name: &str| {
        children
            .iter()
            .find(|child| child.display() == name)
            .unwrap()
    };
    let expected = |name: &str| Expected {
        key: listed(name).key,
        directory: root.path(),
        name: &listed(name).name,
    };

    // A file with one name, in its place, is as admitted.
    let f = root.open_child(listed("f.txt"), INSPECT).unwrap().unwrap();
    recheck(&f.handle, &expected("f.txt"), Names::One).expect("the object is as admitted");

    // A name made after admission: the actions that need one name stop, the others go on.
    fs::hard_link(&file, scratch.path("later.txt")).unwrap();
    let found = recheck(&f.handle, &expected("f.txt"), Names::One).expect_err("a second name");
    assert!(matches!(found, Recheck::Links), "{found:?}");
    recheck(&f.handle, &expected("f.txt"), Names::Any).expect("any number of names is accepted");
    assert_eq!(
        recheck_refusal(&found, "P").detail(),
        format!("P: {RECHECK_LINKS_WORDS}")
    );

    // Another object behind the same name.
    let mut other = listed("f.txt").key;
    other.file_id[0] ^= 1;
    let changed = Expected {
        key: FileKey { ..other },
        ..expected("f.txt")
    };
    let found = recheck(&f.handle, &changed, Names::Any).expect_err("another identity");
    assert!(matches!(found, Recheck::Identity), "{found:?}");

    // An object that was moved out of its folder while a handle on it stayed open.
    let handle = {
        let open = fs::OpenOptions::new()
            .access_mode(0x0002_0000 | 0x0080)
            .share_mode(7)
            .open(&moving)
            .unwrap();
        Handle::new(open.into_raw_handle(), "a file").unwrap()
    };
    recheck(&handle, &expected("g.txt"), Names::One).expect("the file is in its place");
    fs::rename(&moving, scratch.path("moved.txt")).unwrap();
    let found = recheck(&handle, &expected("g.txt"), Names::One).expect_err("the file moved");
    assert!(matches!(found, Recheck::Place), "{found:?}");
}
