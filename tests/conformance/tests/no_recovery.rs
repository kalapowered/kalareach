//! The report recovers nothing: each step runs once and a failed step stays failed. Its own
//! sources, apart from their test modules, start none of the programs that end processes or read
//! the system's logs and signatures, and call no removal of a file or a directory.

use std::path::Path;

/// The programs the report never starts, by the name a command is given or the path's last part.
const PROGRAMS: [&str; 8] = [
    "kill", "pkill", "killall", "taskkill", "ps", "codesign", "log", "sudo",
];

/// Calls that remove from the disk or signal a process.
const CALLS: [&str; 8] = [
    "remove_dir_all",
    "remove_dir(",
    "remove_file(",
    ".kill()",
    "libc::kill",
    "killpg",
    "process_group(",
    "SIGKILL",
];

/// What in `source` removes, signals or starts a program that does: each line with its number. The
/// source's test module, which closes it, and its comments are not read.
fn found(source: &str) -> Vec<String> {
    let code = source.split("#[cfg(test)]").next().unwrap_or_default();
    let mut found = Vec::new();
    for (number, line) in code.lines().enumerate() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        let spawns = line.split("Command::new(").skip(1).any(|rest| {
            rest.trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split('"').next())
                .is_some_and(named)
        });
        let literal =
            line.split('"').skip(1).step_by(2).any(|literal| {
                PROGRAMS.contains(&literal) || named(literal) && literal.contains('/')
            });
        if spawns || literal || CALLS.iter().any(|call| line.contains(call)) {
            found.push(format!("{}: {line}", number + 1));
        }
    }
    found
}

/// Whether a command or a path names one of the programs the report never starts.
fn named(command: &str) -> bool {
    let last = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let last = last.strip_suffix(".exe").unwrap_or(last);
    PROGRAMS.contains(&last)
}

#[test]
fn the_report_s_sources_remove_nothing_and_signal_and_read_no_one() {
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut seen = 0;
    for entry in std::fs::read_dir(&sources).expect("the sources") {
        let path = entry.expect("an entry").path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        seen += 1;
        let source = std::fs::read_to_string(&path).expect("a source");
        let hits = found(&source);
        assert!(hits.is_empty(), "{}: {hits:#?}", path.display());
    }
    assert!(seen > 10, "the sources were not found");
}

#[test]
fn the_check_finds_what_it_is_there_for() {
    for code in [
        "std::process::Command::new(\"kill\")",
        "Command::new(\"/usr/bin/codesign\").arg(path)",
        "Command::new(\"/bin/ps\")",
        "Command::new(\"sudo\")",
        "let log = \"/usr/bin/log\";",
        "std::fs::remove_dir_all(&target)?;",
        "std::fs::remove_file(path)",
        "child.kill();",
        "child.kill()",
        "command.process_group(0);",
    ] {
        assert!(!found(code).is_empty(), "not found: {code}");
    }
    for code in [
        "// Command::new(\"kill\") is never made",
        "let step = Command::new(&words[0]);",
        "Command::new(\"cargo\")",
        "#[cfg(test)]\nmod tests { fn f() { std::fs::remove_dir_all(x); } }",
    ] {
        assert!(found(code).is_empty(), "found in: {code}");
    }
}
