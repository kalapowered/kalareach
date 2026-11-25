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

use common::Scratch;
use common::people::{Person, prepare, runs_as_the_system};
use common::project::{Project, repository_at};

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
