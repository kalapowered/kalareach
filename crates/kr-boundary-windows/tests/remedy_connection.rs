//! The words of the installer's connection to the broker's pipes: the hello that fails and the open
//! that finds every connection in use. Other elevated sessions are named as the cause only where the
//! failure can mean it. They run on every platform.

use std::io;

use kr_boundary_windows::frame::FrameError;
use kr_boundary_windows::remedy::{busy_pipe, hello_failure};

const SESSIONS: &str = "Other elevated sessions may hold the administrators' pipe.";

/// A hello that the read's deadline ended can mean that elevated sessions hold the connections that
/// the broker serves, so that it did not answer in time.
#[test]
fn a_hello_that_the_deadline_ended_names_other_elevated_sessions() {
    let failure = FrameError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "the other end did not answer before the deadline",
    ));
    let text = hello_failure(&failure);
    assert!(
        text.contains("did not answer before the deadline"),
        "{text}"
    );
    assert!(text.ends_with(SESSIONS), "{text}");
}

/// Every other failure of the hello has another cause: a write that failed, a frame that is
/// malformed or too long, a connection that the broker ended (it stops) or a platform error.
#[test]
fn a_hello_that_failed_for_another_reason_does_not_name_other_sessions() {
    let others = [
        FrameError::Closed,
        FrameError::TooLong(1 << 20),
        FrameError::Malformed("not a message".to_owned()),
        FrameError::Io(io::Error::from(io::ErrorKind::BrokenPipe)),
        FrameError::Io(io::Error::from(io::ErrorKind::UnexpectedEof)),
    ];
    for failure in others {
        let text = hello_failure(&failure);
        assert_eq!(text, failure.to_string(), "{failure:?}");
        assert!(!text.contains("elevated sessions"), "{text}");
    }
}

/// An open that found every connection in use says how long it waited. The platform's error follows
/// the words after a colon, so they end without a full stop. Only the administrators' pipe names
/// other elevated sessions.
#[test]
fn a_busy_pipe_names_other_elevated_sessions_only_for_the_administrators_pipe() {
    let administrators = busy_pipe(10, true);
    // The words claim only what the open saw: no instance of the pipe listened. Every connection
    // that the broker serves may be in use, or the broker may have failed to make the next
    // instance, and the words do not say which.
    assert!(
        administrators.contains("no instance of it was listening for 10 seconds"),
        "{administrators}"
    );
    assert!(
        !administrators.contains("every connection"),
        "{administrators}"
    );
    assert!(
        administrators.contains("other elevated sessions may hold the administrators' pipe"),
        "{administrators}"
    );
    let persons = busy_pipe(10, false);
    assert!(
        persons.contains("no instance of it was listening for 10 seconds"),
        "{persons}"
    );
    assert!(!persons.contains("every connection"), "{persons}");
    assert!(!persons.contains("elevated sessions"), "{persons}");
    for text in [administrators, persons] {
        assert!(
            !text.ends_with('.'),
            "the error follows after a colon: {text}"
        );
        assert!(!text.contains(".:"), "{text}");
    }
}
