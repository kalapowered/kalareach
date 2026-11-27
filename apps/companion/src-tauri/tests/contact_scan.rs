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
                told.push((path.clone(), number + 1));
            }
        }
    }
    // A path is read by its components, which hold where the platform's separator is a backslash.
    let outside: Vec<String> = told
        .iter()
        .filter(|(path, _)| {
            !path.ends_with("src/contact.rs") && !path.ends_with("src/connection.rs")
        })
        .map(|(path, number)| format!("{}:{number}", path.display()))
        .collect();
    assert!(
        outside.is_empty(),
        "the event is named outside its publisher: {outside:?}"
    );
    let in_connection: Vec<String> = told
        .iter()
        .filter(|(path, _)| path.ends_with("src/connection.rs"))
        .map(|(path, number)| format!("{}:{number}", path.display()))
        .collect();
    assert_eq!(
        in_connection.len(),
        1,
        "connection.rs only defines the event's name: {in_connection:?}"
    );
    let emits: Vec<String> = told
        .iter()
        .filter(|(path, _)| path.ends_with("src/contact.rs"))
        .map(|(path, number)| format!("{}:{number}", path.display()))
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

/// The lines of `text` that write `field` of a struct, each with the name of the function it is
/// in: an assignment through a field access, a compound assignment, a method that changes an
/// `Option` in place, or a mutable borrow. A struct literal's `field: value`, a lint attribute's
/// `field = "..."`, a comparison and a comment write nothing.
fn writes_of(text: &str, field: &str) -> Vec<(usize, String)> {
    let access = format!(".{field}");
    let mut found = Vec::new();
    let mut function = String::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(name) = function_named(trimmed) {
            function = name;
        }
        let mut from = 0;
        while let Some(found_at) = line[from..].find(&access) {
            let start = from + found_at;
            let end = start + access.len();
            from = end;
            let rest = &line[end..];
            if rest.starts_with(|each: char| each.is_alphanumeric() || each == '_') {
                continue;
            }
            let rest = rest.trim_start();
            let assigns = rest.starts_with('=') && !rest.starts_with("==");
            let compound = ["+=", "-=", "|=", "&=", "^=", "*=", "/="]
                .iter()
                .any(|operator| rest.starts_with(operator));
            let in_place = [".take(", ".replace(", ".insert(", ".get_or_insert"]
                .iter()
                .any(|call| rest.starts_with(call));
            let before = &line[..start];
            let path_start = before
                .rfind(|each: char| !(each.is_alphanumeric() || each == '_' || each == '.'))
                .map_or(0, |at| at + 1);
            let borrowed = before[..path_start].trim_end().ends_with("&mut");
            if assigns || compound || in_place || borrowed {
                found.push((index + 1, function.clone()));
            }
        }
    }
    found
}

/// The name of the function a line declares, when it declares one.
fn function_named(trimmed: &str) -> Option<String> {
    let mut rest = trimmed;
    for prefix in ["pub(crate) ", "pub ", "const ", "async ", "unsafe "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|each| each.is_alphanumeric() || *each == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The scan tells a write from a literal, a lint attribute, a comparison and a comment, so that it
/// finds the writes it is meant to and none it is not.
#[test]
fn the_scan_of_the_writes_tells_a_write_from_what_only_names_the_field() {
    let sample = "\
fn new() -> State {
    let state = State { reason: None, cause: Cause::Own };
    state
}
#[expect(clippy::too_many_arguments, reason = \"the call\")]
fn read(state: &State) -> bool {
    // state.reason = None;
    state.reason == None && state.reasons.is_empty()
}
fn stray(state: &mut State) {
    state.reason = None;
    let own = &mut state.cause;
    state.slow |= true;
    state.reason.take();
}
";
    assert_eq!(
        writes_of(sample, "reason"),
        vec![(11, "stray".to_owned()), (14, "stray".to_owned())]
    );
    assert_eq!(writes_of(sample, "cause"), vec![(12, "stray".to_owned())]);
    assert_eq!(writes_of(sample, "slow"), vec![(13, "stray".to_owned())]);
}

/// The words a person reads while no connection is held, and what they are the words of, change in
/// one place: the setter. A writer that assigned the reason by itself would leave the cause of the
/// words before it.
#[test]
fn the_standing_words_are_written_in_one_place() {
    let text =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/contact.rs"))
            .expect("a readable file");
    let mut strays = Vec::new();
    let mut missing = Vec::new();
    for (field, allowed) in [
        ("reason", &["set_reason"][..]),
        ("cause", &["set_reason"][..]),
    ] {
        let writes = writes_of(&text, field);
        for (number, function) in &writes {
            if !allowed.contains(&function.as_str()) {
                strays.push(format!("{field} at src/contact.rs:{number} in {function}"));
            }
        }
        for name in allowed {
            if !writes.iter().any(|(_, function)| function == name) {
                missing.push(format!("{field} in {name}"));
            }
        }
    }
    assert!(strays.is_empty(), "writes outside their place: {strays:?}");
    assert!(
        missing.is_empty(),
        "the scan finds no write where one is expected: {missing:?}"
    );
}
