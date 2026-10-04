//! The forwarder's path, written by the host into a shell line, is read by a real POSIX shell as one
//! word whatever it holds.
//!
//! The package's line is `{kr_hook} gemini-cli hook`. The host writes the path where the placeholder
//! is, and a shell runs the line. Each case puts a stand-in forwarder at a path of its own, a script
//! that writes the arguments it was started with beside itself, and checks that the shell started
//! exactly that program with exactly the package's two arguments, and that nothing the path's
//! characters could mean to a shell ran.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use kr_plugin_sdk::forwarder::expand;

/// Directory names a person's machine can have, each with a character a shell reads as syntax.
const NAMES: &[&str] = &[
    "plain",
    "with space",
    "it's",
    "dollar$HOME",
    "back`echo planted`tick",
    "amp&semi;pipe|redirect>less<",
    "percent%d",
    "double\"quote",
    "back\\slash",
    "\u{e9}\u{4e2d}\u{1f600}",
    "x'; touch PLANTED; '",
    "$(touch PLANTED)",
    "*",
    "-n",
    "~",
    "#hash",
    "!bang",
];

/// A stand-in forwarder: it writes its arguments, one to a line, to `arguments` beside itself.
fn stand_in(directory: &Path) -> std::path::PathBuf {
    let program = directory.join("kr-hook");
    std::fs::write(
        &program,
        "#!/bin/sh\nfor argument in \"$@\"; do printf '%s\\n' \"$argument\"; done > \"$(dirname \"$0\")/arguments\"\n",
    )
    .expect("the stand-in is written");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("and made runnable");
    program
}

#[test]
fn a_shell_runs_exactly_the_forwarder_whatever_its_path_holds() {
    let root = tempfile::tempdir().expect("a directory");
    for name in NAMES {
        let directory = root.path().join(name);
        std::fs::create_dir(&directory).expect("a directory with this name");
        let program = stand_in(&directory);

        let template = r#"{"command": "{kr_hook} gemini-cli hook"}"#;
        let expanded = expand(template, &program).expect("expands");
        let line = serde_json::from_str::<serde_json::Value>(&expanded).expect("JSON")["command"]
            .as_str()
            .expect("a line")
            .to_owned();

        // The directory the line runs in is the root, where a file named as an attack would be
        // made if the shell ran it.
        let ran = Command::new("/bin/sh")
            .arg("-c")
            .arg(&line)
            .current_dir(&directory)
            .output()
            .expect("the shell runs");
        assert!(
            ran.status.success(),
            "{name}: {line}: {}",
            String::from_utf8_lossy(&ran.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(directory.join("arguments")).expect("the stand-in ran"),
            "gemini-cli\nhook\n",
            "{name}: the shell started the forwarder with the package's arguments and nothing else"
        );
        assert!(
            !directory.join("PLANTED").exists() && !root.path().join("PLANTED").exists(),
            "{name}: nothing the path's characters spell ran"
        );
        assert!(
            ran.stdout.is_empty() && ran.stderr.is_empty(),
            "{name}: the shell wrote nothing of its own: {}",
            String::from_utf8_lossy(&ran.stderr)
        );
    }
}
