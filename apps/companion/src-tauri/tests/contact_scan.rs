//! What the source says about who tells the page the connection, and who starts the one task that
//! does.

use std::path::{Path, PathBuf};

/// Every Rust file under `dir`.
fn files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a readable directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn sources(under: &str) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join(under),
        &mut found,
    );
    found
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a readable file");
            (path, text)
        })
        .collect()
}

/// The connection's changes reach the page from one place: the publisher, which tells each
/// publication once and in order. A second path could tell one out of order.
#[test]
fn the_connection_event_is_told_only_by_the_publisher() {
    let mut told = Vec::new();
    for (path, text) in sources("src") {
        for (number, line) in text.lines().enumerate() {
            if line.contains("CONNECTION_EVENT") && !line.trim_start().starts_with("//") {
                told.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    let outside: Vec<&String> = told
        .iter()
        .filter(|place| !place.contains("src/contact.rs") && !place.contains("src/connection.rs"))
        .collect();
    assert!(
        outside.is_empty(),
        "the event is named outside its publisher: {outside:?}"
    );
    let in_connection: Vec<&String> = told
        .iter()
        .filter(|place| place.contains("src/connection.rs"))
        .collect();
    assert_eq!(
        in_connection.len(),
        1,
        "connection.rs only defines the event's name: {in_connection:?}"
    );
    let emits: Vec<&String> = told
        .iter()
        .filter(|place| place.contains("src/contact.rs"))
        .collect();
    assert!(
        emits.len() <= 3,
        "the publisher names the event for its tap, its emit and its import: {emits:?}"
    );
}

/// Every place that manages the application's state starts the publisher, in the same file.
#[test]
fn every_place_that_manages_the_state_starts_the_publisher() {
    let mut missing = Vec::new();
    for under in ["src", "tests"] {
        for (path, text) in sources(under) {
            let manages = text.contains(".manage(AppState::new())")
                || text.contains(".manage(companion_tauri::AppState::new())")
                || text.contains("manage(state)");
            if manages && !text.contains("contact::serve(") {
                missing.push(path.display().to_string());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these files manage the state and never start the publisher: {missing:?}"
    );
}

/// The owner is asked first and the device after it: the device's records are read from disk, and
/// the owner's mutex is never held across that read.
#[test]
fn the_device_is_asked_after_the_owner_has_answered() {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/state.rs"))
        .expect("a readable file");
    let body = text
        .split("pub fn paired_context(")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("the function is there");
    let held = body
        .find("self.contact.stand()")
        .expect("the owner is asked");
    let device = body.find("host_in_use()").expect("the device is asked");
    assert!(
        held < device,
        "the owner answers before the device is asked: {body}"
    );
    assert!(
        !body.contains("contact_owner()"),
        "no handle on the owner is kept while the device is asked: {body}"
    );
}
