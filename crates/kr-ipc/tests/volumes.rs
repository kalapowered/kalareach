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
    drop(volume);
}
