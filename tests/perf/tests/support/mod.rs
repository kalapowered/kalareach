//! A caller's evidence folder, as the helpers that start `scripts/performance.sh` inherit it.
//!
//! A helper gives the script a temporary folder of its own, so a folder that its caller named
//! under the caller's temporary folder is outside the script's roots. The helper must not hand it
//! on. A case cannot change the environment that its own program inherited, so it starts the
//! program again with the environment that a caller sets, and the case that the program is told to
//! run is one that starts the script through the helper.
//!
//! Unix only, as the files that include it are.

use std::path::Path;
use std::process::Command;

/// Whether `folder` is outside `/tmp`, which every reader takes as a root. The two are compared by
/// their real paths: `/tmp` is a link on macOS and can be one elsewhere, so neither `/tmp` nor
/// `/private/tmp` is the name to compare with.
fn is_outside_tmp(folder: &Path) -> bool {
    let physical = std::fs::canonicalize(folder).expect("resolves");
    match std::fs::canonicalize("/tmp") {
        Ok(temporary) => !physical.starts_with(temporary),
        Err(_) => true,
    }
}

/// Runs `case` of the calling test program in a program of its own, as a caller runs it that sets
/// its temporary folder and the evidence directory under it. The caller's folder is a folder of its
/// own in the build folder, or in `/var/tmp` where the build folder is under `/tmp`, so that it is
/// outside `/tmp`. The evidence directory stands beside the folder that the case gives the script as
/// its temporary folder, not inside it, so the script's reader refuses the directory if the helper
/// passes it on.
pub fn run_as_a_caller_with_an_evidence_folder(case: &str) {
    let build = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let parent = if is_outside_tmp(build) {
        build
    } else {
        Path::new("/var/tmp")
    };
    let caller = tempfile::tempdir_in(parent)
        .unwrap_or_else(|error| panic!("a caller's folder in {}: {error}", parent.display()));
    assert!(
        is_outside_tmp(caller.path()),
        "this case needs a folder outside /tmp, and neither the build folder nor /var/tmp is \
         one: {} is inside it",
        caller.path().display()
    );
    let physical = std::fs::canonicalize(caller.path()).expect("resolves");
    let output = Command::new(std::env::current_exe().expect("this program"))
        .args([case, "--exact", "--test-threads=1"])
        .env("TMPDIR", &physical)
        .env("KR_TEST_ARTIFACTS_DIR", physical.join("evidence"))
        .env_remove("RUNNER_TEMP")
        .output()
        .expect("the program runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && text.contains("1 passed; 0 failed"),
        "{case} fails when its caller names an evidence directory under the caller's temporary \
         folder:\n{text}"
    );
}
