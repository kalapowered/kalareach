//! The record the system keeps of the account a host runs as.
//!
//! A system that keeps its accounts in a directory service, as macOS does for a person's own
//! account, has no line for that account in the account file. The record is the system's own
//! answer, from whichever database holds the account, and the account tool of the platform gives
//! the same name.

#![cfg(unix)]

/// KR-REQ-07.25: the user this process runs as has a record with the name the platform's own tool
/// gives and a home that is an absolute path, wherever the account is kept. A session a daemon with
/// no `HOME` starts takes this home, so a record the lookup missed would leave it at the root.
#[test]
fn the_current_users_record_is_the_systems_answer_wherever_the_account_is_kept() {
    let named = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the platform's account tool runs");
    assert!(named.status.success(), "the account tool names the user");
    let name = String::from_utf8(named.stdout).expect("a name that is text");

    let entry = kr_ipc::paths::passwd_entry()
        .expect("the system has a record of the account this process runs as");
    assert_eq!(entry.name, name.trim());
    let home = entry.home.expect("the record names a home");
    assert!(
        home.starts_with('/'),
        "the account's home is an absolute path: {home:?}"
    );
}
