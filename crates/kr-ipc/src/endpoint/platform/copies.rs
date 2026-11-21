//! The cases that show a lock ends with its holder while a program keeps a copy of the lock file.

use std::fs::File;
use std::process::{Child, Command, Stdio};

use super::EndpointGuard;
use crate::testing::PrivateTempDir;

/// A running program that holds a copy of an open file as its input.
///
/// It stands for a program that another thread starts while a lock is held: the copy shares the
/// open file, and so the lock, until the program ends or its own program takes over. This one
/// stays, so a case can read the lock while the copy is there.
pub(in crate::endpoint) struct ProgramWithACopy(Child);

impl ProgramWithACopy {
    /// Starts the program, which has run its own program when this returns.
    pub(in crate::endpoint) fn of(file: &File) -> Self {
        let copy = file.try_clone().expect("a copy of the file");
        let child = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::from(copy))
            .spawn()
            .expect("a program that waits");
        Self(child)
    }
}

impl Drop for ProgramWithACopy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The guard's lock ends with the guard, though a program keeps a copy of its file: the next
/// guard on the address is taken at once and does not wait for that program.
#[test]
fn the_guard_ends_with_its_holder_though_a_program_keeps_a_copy_of_its_file() {
    let folder = PrivateTempDir::create();
    let path = folder.path().join("guarded.sock");
    let guard = EndpointGuard::take(&path).expect("the guard");
    let _program = ProgramWithACopy::of(&guard.file);
    drop(guard);
    EndpointGuard::take(&path).expect("the guard is free once its holder ended");
}
