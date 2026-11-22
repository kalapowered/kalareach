//! A disk image a test attached comes off when the system lets its disk go, however long that takes.
//!
//! A detach that is forced unmounts the volume and then fails to eject its disk when a process has
//! the disk's device open, and the disk stays attached with nothing mounted from it. This case
//! holds a disk as the system can, and shows that the detach asks again, by the disk, until the
//! hold is gone.

#![cfg(target_os = "macos")]

use std::path::Path;
use std::time::Duration;

use kr_ipc::testing::volumes::{self, Volume};

/// How long a case lets a detach ask before it takes the case for hung. It ends a case that is
/// never let go of and decides nothing else.
const HUNG: Duration = Duration::from_secs(300);

/// A volume attached in a directory of its own, and the directory it is attached from.
fn attached(scratch: &kr_ipc::testing::PrivateTempDir, tag: &str) -> (std::path::PathBuf, Volume) {
    let at = scratch.path().join(format!("volume-{tag}"));
    std::fs::create_dir(&at).expect("a mount point");
    let volume =
        Volume::attach(&at, scratch.path(), tag).unwrap_or_else(|| volumes::not_attachable());
    (at, volume)
}

/// Whether the disk's device is still there, which it is for as long as the image is attached.
fn attached_still(disk: &str) -> bool {
    Path::new(disk).exists()
}

/// A volume whose disk a process has open is unmounted by a forced detach and then not ejected, and
/// stays attached. The detach asks again until the process lets go, and the disk goes with it. The
/// process lets go once the system has refused the eject, which is the refusal this case is about;
/// any other refusal the system makes while it holds the disk is asked through.
#[test]
fn a_volume_whose_disk_is_held_is_detached_once_it_is_let_go() {
    let scratch = kr_ipc::testing::PrivateTempDir::create();
    let (at, volume) = attached(&scratch, "held-disk");
    let disk = volumes::disk_of(&at).expect("the volume is on a disk");
    let mut holder = Some(std::fs::File::open(&disk).expect("the disk opens for reading"));

    let mut refusals = Vec::new();
    volumes::detach_observed(&at, HUNG, |said| {
        refusals.push(said.to_owned());
        if said.contains("couldn't eject") {
            drop(holder.take());
        }
    })
    .expect("the volume comes off once the disk is let go");

    assert!(
        holder.is_none(),
        "the disk was held until the system refused to eject it: {refusals:?}"
    );
    assert!(!attached_still(&disk), "{disk} is gone");
    // The case took the volume off itself, so there is nothing for the volume's own detach to find:
    // it would fail the case for a volume that is already gone.
    std::mem::forget(volume);
}

/// A disk that stays held for the whole of the patience fails with what holds it: the process that
/// has the disk open, by number and name, and the case then lets the disk go and takes the volume
/// off. A volume that could not be detached without that is reported as one nothing explains.
#[test]
fn a_disk_that_stays_held_is_reported_with_the_process_that_holds_it() {
    let scratch = kr_ipc::testing::PrivateTempDir::create();
    let (at, volume) = attached(&scratch, "named-holder");
    let disk = volumes::disk_of(&at).expect("the volume is on a disk");
    let holder = std::fs::File::open(&disk).expect("the disk opens for reading");

    let held = volumes::detach_observed(&at, Duration::from_secs(3), |_| {});

    // The disk is let go and taken off before anything is asserted, so a case that fails does not
    // leave the image attached. The first forced detach unmounted the volume and was refused the
    // eject, so nothing is mounted from the image any longer and the disk is what is asked about.
    drop(holder);
    let off = volumes::detach_disk(&at, &disk, HUNG, |_| {});
    let gone = !attached_still(&disk);
    // The case took the volume off itself, so there is nothing for the volume's own detach to find.
    std::mem::forget(volume);

    off.expect("the disk comes off once it is let go");
    assert!(gone, "{disk} is gone");
    let why = held.expect_err("a disk that is held for the whole of the patience stays attached");
    assert!(
        why.contains(&format!("process {} (", std::process::id())),
        "the report names the process that holds the disk: {why}"
    );
    assert!(why.contains(&disk), "and the disk it holds open: {why}");
}
