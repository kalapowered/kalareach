//! The environment a launch gives its program, run on Windows.
//!
//! A start gives its program exactly the environment it is handed and adds nothing of this worker's
//! own. The program here is `cmd.exe`, which prints a variable it has and the name of one it has not,
//! so what the program was given is read from what it says.
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-07.45 | A program started with an empty environment starts and sees no variable; a program sees the variables it is given and none of this worker's own; a value given for a name of this worker's own, spelled in any case, replaces it |

#![cfg(windows)]

use std::io::Read as _;

use kr_worker::windows::job::AgentJob;
use kr_worker::windows::launch::{Environment, Spec, start};

fn system_program(name: &str) -> std::path::PathBuf {
    std::path::Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
        .join("System32")
        .join(name)
}

/// What `cmd.exe` prints for `line`, run in `environment`: a variable it has is replaced by its
/// value and one it has not is printed as it was written.
fn said(environment: &Environment, line: &str) -> (String, i32) {
    let job = AgentJob::create_owning().expect("a job");
    let arguments = ["/d".to_owned(), "/c".to_owned(), line.to_owned()];
    let mut child = start(&Spec {
        program: &system_program("cmd.exe"),
        arguments: &arguments,
        directory: &std::env::temp_dir(),
        environment,
        session: None,
        agent: &job,
        pipe_input: false,
        pipe_output: true,
    })
    .expect("cmd.exe starts");
    let mut text = String::new();
    child
        .stdout
        .take()
        .expect("an output")
        .read_to_string(&mut text)
        .expect("the output reads");
    let status = child.wait().expect("cmd.exe ends");
    (text.trim().to_owned(), status.code().expect("an exit code"))
}

/// One variable, as the block holds it.
fn variable(name: &str, value: &std::ffi::OsStr) -> (Vec<u16>, Vec<u16>) {
    use std::os::windows::ffi::OsStrExt as _;
    (
        std::ffi::OsStr::new(name).encode_wide().collect(),
        value.encode_wide().collect(),
    )
}

/// An empty environment is two terminators, which `CreateProcessW` reads, and not one it reads past.
/// The program starts, exits cleanly and has no variable of any name.
#[test]
fn a_program_starts_with_an_empty_environment() {
    let (text, code) = said(
        &Environment::default(),
        "echo [%KR_NO_SUCH%][%PATH%][%SystemRoot%]",
    );
    assert_eq!(code, 0);
    assert_eq!(text, "[%KR_NO_SUCH%][%PATH%][%SystemRoot%]");
}

/// KR-REQ-07.45: the program sees the variables it is given and none of this worker's own.
#[test]
fn a_program_sees_the_variables_it_is_given_and_none_of_this_workers() {
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "this program has a variable that the set below does not"
    );
    let environment =
        Environment::from_variables(vec![variable("KR_GIVEN", std::ffi::OsStr::new("given"))])
            .expect("an environment");
    let (text, code) = said(&environment, "echo [%KR_GIVEN%][%CARGO_MANIFEST_DIR%]");
    assert_eq!(code, 0);
    assert_eq!(text, "[given][%CARGO_MANIFEST_DIR%]");
}

/// KR-REQ-07.45: a value given for a name of this worker's own, spelled in another case, replaces it.
#[test]
fn a_given_value_replaces_a_workers_own_of_the_same_name_in_any_case() {
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "this program has the variable the set below replaces"
    );
    let environment =
        Environment::of_this_process_with(&[("cargo_manifest_dir", std::ffi::OsStr::new("given"))])
            .expect("an environment");
    let (text, code) = said(&environment, "echo [%CARGO_MANIFEST_DIR%]");
    assert_eq!(code, 0);
    assert_eq!(text, "[given]");
}
