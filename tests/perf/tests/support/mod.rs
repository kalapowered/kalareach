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

/// What the case needs where the build folder is under `/tmp`, as the failure says it.
const VAR_TMP_NEED: &str = " The build folder is under /tmp, so this case needs a /var/tmp that \
                            exists, can be written, lets programs run and is not inside /tmp, as \
                            the README says of the clean-checkout check.";

/// Runs `case` of the calling test program in a program of its own, as a caller runs it that sets
/// its temporary folder and the evidence directory under it. The caller's folder is a folder of its
/// own, named `kr-perf-caller.` and a suffix, in the build folder, or in `/var/tmp` where the build
/// folder is under `/tmp`, so that it is outside `/tmp`. The helper removes that folder, and only
/// that one, by its exact path; a run that is killed leaves it, and the prefix finds it. The
/// evidence directory stands in the caller's folder beside the case's own folder, which holds the
/// script's temporary folder, and not inside the script's temporary folder, so the script's reader
/// refuses the directory if the helper passes it on.
///
/// Where the build folder is under `/tmp`, the case needs a `/var/tmp` that exists, can be written,
/// lets programs run and is not itself inside `/tmp`, as the README says of the clean-checkout
/// check. It looks in no other folder and never skips. A `/var/tmp` that is absent or cannot be
/// written, or that is inside `/tmp`, fails the case with words that name this need. A `/var/tmp`
/// where programs cannot run fails the case at the script's start, where the nested program's text
/// shows that a stand-in did not start.
pub fn run_as_a_caller_with_an_evidence_folder(case: &str) {
    let build = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let (parent, need) = if is_outside_tmp(build) {
        (build, "")
    } else {
        (Path::new("/var/tmp"), VAR_TMP_NEED)
    };
    let caller = tempfile::Builder::new()
        .prefix("kr-perf-caller.")
        .tempdir_in(parent)
        .unwrap_or_else(|error| {
            panic!(
                "a caller's folder cannot be made in {}: {error}.{need}",
                parent.display()
            )
        });
    let physical = std::fs::canonicalize(caller.path()).expect("resolves");
    assert!(
        is_outside_tmp(&physical),
        "the caller's folder {} is inside /tmp, which every reader takes as a root, and this case \
         needs a folder outside it.{need}",
        physical.display()
    );
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
