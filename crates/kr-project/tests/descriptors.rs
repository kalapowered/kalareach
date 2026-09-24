//! Every descriptor the project service holds is closed when a child it starts executes.
//!
//! A kernel rule on reading is judged when a file is opened, and a descriptor opened before the
//! rules is already open: Git would read through one it inherited whatever the rules say. So every
//! descriptor this service opens is marked to close on execution, and the launcher marks every
//! other one from the fourth on as well. This is the first half, on its own in this test program
//! so that no other test opens descriptors while it counts them.

#![cfg(feature = "git-fixtures")]
#![cfg(target_os = "linux")]

mod support;

use std::collections::BTreeMap;
use std::ffi::OsStr;

use kr_project::git::{GitRequest, RemoteAccess};
use kr_project::identity::OpenedRepository;

use support::Fixture;

/// Returns every descriptor this process holds, and what each one is.
///
/// Not the one the listing is read through, which is open only while this reads it: its number is
/// free again afterwards, and a descriptor the service opens later may take it.
fn descriptors() -> BTreeMap<i32, String> {
    let listing = std::fs::canonicalize("/proc/self/fd").expect("this process's descriptor list");
    let mut held = BTreeMap::new();
    for entry in std::fs::read_dir(&listing).expect("this process's descriptors") {
        let entry = entry.expect("a descriptor entry");
        let Ok(number) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let target = std::fs::read_link(entry.path())
            .map(|target| target.display().to_string())
            .unwrap_or_default();
        if std::path::Path::new(&target) == listing {
            continue;
        }
        held.insert(number, target);
    }
    held
}

/// Returns whether a descriptor this process holds is marked to close on execution, or nothing
/// when it is no longer held.
///
/// Read from the kernel's own account of the descriptor, whose flags carry the close-on-exec bit
/// when the descriptor has it.
fn closes_on_execution(number: i32) -> Option<bool> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{number}")).ok()?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())?;
    let close_on_exec = u32::try_from(libc::O_CLOEXEC).expect("a flag");
    Some(flags & close_on_exec != 0)
}

#[test]
fn every_descriptor_the_project_service_opens_is_closed_when_a_child_executes() {
    // The control first: a descriptor opened the ordinary way is marked, and the same descriptor
    // with the mark taken away is one this check reports.
    let probe = std::fs::File::open("/proc/self/status").expect("a file to hold open");
    let number = std::os::fd::AsRawFd::as_raw_fd(&probe);
    assert_eq!(
        closes_on_execution(number),
        Some(true),
        "opened with the mark"
    );
    rustix::io::fcntl_setfd(&probe, rustix::io::FdFlags::empty()).expect("the mark is taken away");
    assert_eq!(
        closes_on_execution(number),
        Some(false),
        "and without it the check sees a descriptor a child would inherit"
    );
    drop(probe);

    let before = descriptors();
    // The service opened on a host tree: its store, its journal, its profile and the handles it
    // keeps. Then a repository opened and cloned through it, which holds handles of its own.
    let fixture = Fixture::create();
    let profile = fixture.service().profile();
    let path = support::ordinary_repository(fixture.work(), "held");
    let repository = OpenedRepository::open(profile, fixture.environment_id(), &path)
        .expect("the repository opens");
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
                .with_transport(RemoteAccess::local()),
        )
        .expect("the clone starts");
    assert!(cloned.success, "the clone runs: {}", cloned.stderr);

    // New, or a number that now holds something else: a descriptor closed and reopened between
    // the two readings is a descriptor the service opened.
    let opened: Vec<(i32, String)> = descriptors()
        .into_iter()
        .filter(|(number, target)| before.get(number) != Some(target))
        .collect();
    assert!(
        !opened.is_empty(),
        "the service holds descriptors of its own, so there is something to count"
    );
    for (number, target) in &opened {
        if let Some(closes) = closes_on_execution(*number) {
            assert!(
                closes,
                "descriptor {number} on {target} would be inherited by a child the service starts"
            );
        }
    }
    drop(repository);
}
