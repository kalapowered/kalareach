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

/// Runs `case` of the calling test program in a program of its own, as a caller runs it that sets
/// its temporary folder and the evidence directory under it. The folder is outside `/tmp` and
/// outside the temporary folder that the helper's own folders are made under, so the script's
/// reader refuses the caller's directory if the helper passes it on.
pub fn run_as_a_caller_with_an_evidence_folder(case: &str) {
    let caller = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("a caller's folder");
    let physical = std::fs::canonicalize(caller.path()).expect("resolves");
    assert!(
        !["/tmp", "/private/tmp"]
            .iter()
            .any(|root| physical.starts_with(Path::new(root))),
        "this case needs a build folder outside /tmp, and {} is inside it",
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
