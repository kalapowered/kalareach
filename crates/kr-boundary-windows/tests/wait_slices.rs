//! Every wait that the stop's event can end is made in slices, read from the source (the code is
//! Windows-only, so these cases run on every platform):
//!
//! - the stop's own wait, `Stop::wait_for`, is the one call to the platform's wait on the stop's
//!   event: it loops in slices of `STOP_SLICE` at most, reads the stop's kept failure before each
//!   slice, and ends at the bound as one wait would, with no end where the bound is `INFINITE`;
//! - `Stop::wait` and the private `waited` go through it and wait on nothing themselves;
//! - `Child::wait_or_stop` goes through it and makes no wait of its own;
//! - the pipe's wait passes what is left of its deadline to it and slices nothing itself.

use std::fs;

fn source(file: &str) -> String {
    fs::read_to_string(format!("{}/src/win/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The product code of a file: the unit cases at its end are left out, since they call what they
/// test, and no comment or doc line is kept.
fn code_of(file: &str) -> String {
    let text = source(file);
    let end = text.find("\n#[cfg(test)]\n").unwrap_or(text.len());
    text[..end]
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text of the function that starts with `signature`, to the closing brace that stands at the
/// indent of its signature.
fn body_of<'a>(code: &'a str, signature: &str) -> &'a str {
    let start = code
        .find(signature)
        .unwrap_or_else(|| panic!("no function starts with {signature}"));
    let line_start = code[..start].rfind('\n').map_or(0, |at| at + 1);
    let indent = &code[line_start..start];
    let close = format!("\n{indent}}}\n");
    let end = code[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("{signature} has no end"));
    &code[start..start + end]
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

#[test]
fn the_stops_wait_is_the_one_wait_on_its_event_and_it_slices() {
    let stop = code_of("stop.rs");
    assert_eq!(
        count(&stop, "ffi::wait_any("),
        1,
        "the stop's module waits on its event in more or fewer places"
    );
    let wait_for = body_of(&stop, "pub(super) fn wait_for(");
    assert_eq!(count(wait_for, "ffi::wait_any("), 1);
    // The slice is one `STOP_SLICE` at most, and it is cut short by the bound's end.
    assert!(wait_for.contains("loop {"), "{wait_for}");
    assert!(wait_for.contains(".min(STOP_SLICE)"), "{wait_for}");
    assert!(
        wait_for.contains("end.saturating_duration_since(Instant::now())"),
        "{wait_for}"
    );
    // The kept failure is read in the loop, before the wait of each slice.
    let kept = wait_for
        .find("self.unread.get().is_some()")
        .expect("the kept failure is read in the wait");
    let wait = wait_for.find("ffi::wait_any(").unwrap();
    assert!(
        wait_for.find("loop {").unwrap() < kept && kept < wait,
        "the kept failure is read before each slice, inside the loop"
    );
    // A slice that nothing ended goes on while the bound has not run out; `INFINITE` has no end.
    assert!(
        wait_for
            .contains("Ok(ffi::Waited::TimedOut) if end.is_none_or(|end| Instant::now() < end)"),
        "{wait_for}"
    );
    assert!(wait_for.contains("(bound != INFINITE)"), "{wait_for}");
    // A failed wait is kept, sets the event and ends the wait with its error.
    assert!(wait_for.contains("Failure::Wait("), "{wait_for}");
    assert!(wait_for.contains("return Err(failure)"), "{wait_for}");
    // The slice is one second.
    assert!(
        stop.contains("pub(super) const STOP_SLICE: Duration = Duration::from_secs(1);"),
        "the slice is not one second"
    );
}

#[test]
fn no_other_wait_on_the_stop_is_made_in_one_call() {
    let stop = code_of("stop.rs");
    for signature in ["fn waited(", "pub fn wait("] {
        let body = body_of(&stop, signature);
        assert_eq!(count(body, "ffi::wait_any("), 0, "{signature}: {body}");
        assert_eq!(count(body, "ffi::wait("), 0, "{signature}: {body}");
    }
    assert!(body_of(&stop, "fn waited(").contains("self.wait_for("));
    // A wait that failed reads as the stop: the failure was kept, and every reader sees it set.
    assert!(body_of(&stop, "fn waited(").contains("Err(_) => true,"));
    assert!(body_of(&stop, "pub fn wait(").contains("self.waited("));
    assert!(body_of(&stop, "pub fn is_set(").contains("self.waited(0)"));

    let launch = code_of("launch.rs");
    let wait_or_stop = body_of(&launch, "pub fn wait_or_stop(");
    assert!(wait_or_stop.contains("stop.wait_for("), "{wait_or_stop}");
    assert_eq!(count(wait_or_stop, "ffi::wait"), 0, "{wait_or_stop}");

    // No other module waits on the platform's multiple wait: the stop's is the one.
    for file in [
        "account.rs",
        "acl.rs",
        "applocker.rs",
        "boot.rs",
        "broker.rs",
        "fresh.rs",
        "install.rs",
        "job.rs",
        "journal.rs",
        "launch.rs",
        "pipe.rs",
        "privilege.rs",
        "proof.rs",
        "registry.rs",
        "root.rs",
        "sd.rs",
        "service.rs",
        "setup.rs",
        "token.rs",
        "verify.rs",
        "walk.rs",
    ] {
        assert_eq!(
            count(&code_of(file), "ffi::wait_any("),
            0,
            "{file} waits on the platform's multiple wait itself"
        );
    }
}

#[test]
fn the_pipes_wait_hands_its_deadline_to_the_stop_and_slices_nothing_itself() {
    let pipe = code_of("pipe.rs");
    assert_eq!(
        count(&pipe, "STOP_SLICE"),
        0,
        "the pipe's module slices a wait of its own"
    );
    let wait = body_of(&pipe, "fn wait(");
    assert_eq!(count(wait, "loop {"), 0, "{wait}");
    assert!(
        wait.contains("stop.wait_for(&[transfer.event.raw()], bound,"),
        "{wait}"
    );
    // What is left of the deadline, rounded up to a whole millisecond so that the wait never ends
    // before the deadline, or `INFINITE` where there is none.
    assert!(
        wait.contains("deadline.map_or(INFINITE, |deadline| {"),
        "{wait}"
    );
    assert!(wait.contains("Duration::from_nanos(999_999)"), "{wait}");
}
