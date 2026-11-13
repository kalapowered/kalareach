//! The setup program's command line, read before anything of the machine: a wrong command or a bad
//! option gets the usage and its exit code, whatever state the known folders are in. They run on
//! every platform.

use std::path::PathBuf;

use kr_boundary_windows::setup_args::{Command, Rejected, USAGE, USAGE_EXIT, parse};

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn rejected(words: &[&str]) -> Rejected {
    parse(&arguments(words)).expect_err("the command line is refused")
}

/// A command line with no command, or one that is not a command, is refused with the usage alone.
#[test]
fn no_command_and_a_wrong_command_get_the_usage() {
    assert_eq!(rejected(&[]), Rejected { message: None });
    assert_eq!(rejected(&["frobnicate"]), Rejected { message: None });
    assert_eq!(rejected(&["--payload", "D"]), Rejected { message: None });
    assert_eq!(USAGE_EXIT, 2);
    for command in ["install", "repair", "remove", "status"] {
        assert!(USAGE.contains(command), "{USAGE}");
    }
}

/// A bad option of an installation or a repair is refused with its own words, for the usage to
/// follow: a missing value, an option that is not one, and a missing payload.
#[test]
fn a_bad_option_gets_its_words_and_the_usage() {
    for (words, message) in [
        (&["install", "--payload"][..], "--payload needs a directory"),
        (
            &["repair", "--payload", "D", "--person"][..],
            "--person needs an identifier",
        ),
        (
            &["install", "--payload", "D", "--bogus"][..],
            "unknown argument --bogus",
        ),
        (
            &["install"][..],
            "--payload names the directory with the broker and the credential helper",
        ),
        (
            &["repair", "--person", "S-1-5-21"][..],
            "--payload names the directory with the broker and the credential helper",
        ),
    ] {
        assert_eq!(
            rejected(words),
            Rejected {
                message: Some(message.to_owned())
            },
            "{words:?}"
        );
    }
}

/// The good command lines are read as they were: an installation and a repair take a payload and
/// may take a person, a removal and a status take no option.
#[test]
fn the_good_command_lines_are_read() {
    assert_eq!(
        parse(&arguments(&["install", "--payload", "D:\\payload"])),
        Ok(Command::Install {
            repair: false,
            payload: PathBuf::from("D:\\payload"),
            person: None
        })
    );
    assert_eq!(
        parse(&arguments(&[
            "repair",
            "--person",
            "S-1-5-21-1",
            "--payload",
            "D:\\payload"
        ])),
        Ok(Command::Install {
            repair: true,
            payload: PathBuf::from("D:\\payload"),
            person: Some("S-1-5-21-1".to_owned())
        })
    );
    assert_eq!(parse(&arguments(&["remove"])), Ok(Command::Remove));
    assert_eq!(parse(&arguments(&["status"])), Ok(Command::Status));
}
