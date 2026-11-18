//! What the program and its guides tell a person to type: each `kr host` command a text names is
//! one the program has, and each command that ends a process by force is the forced one.
//!
//! The scan reads the product's own strings, the `///` lines that become a command's help, and the
//! guides. It does not judge whether a remedy works; a remedy's accuracy is read in review.
//!
//! Its limits: it stops at a source file's test module, whether the module is private (`mod `) or
//! crate-visible and named `tests` (`pub(crate) mod tests`), so a text after that module is not
//! read, and a crate-visible module of any other name does not end the scan; it skips the `tests`
//! folders and every comment that is not help; and it reads every guide under
//! `docs` except the conformance document, which lists the words of a source check and gives no
//! person an instruction. It also misses a command's word that follows a string continuation (a
//! `kr host` at the end of one line of a string and its word at the start of the next), and a plain
//! `kill` with a process number, which is not the forced one and carries no signal for the scan to
//! read.

use std::path::{Path, PathBuf};

use clap::CommandFactory as _;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every file under `root` with one of the extensions, skipping build output and dependencies.
fn files(root: &Path, extensions: &[&str], found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == "node_modules" || name.to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            files(&path, extensions, found);
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extensions.contains(&extension))
        {
            found.push(path);
        }
    }
}

/// Whether a source file defines command-line arguments by derive, so that the `///` lines of its
/// items are the help a person reads.
fn makes_help(source: &str) -> bool {
    source.lines().any(|line| {
        line.contains("derive(")
            && ["Parser", "Subcommand", "Args", "ValueEnum"]
                .iter()
                .any(|name| line.contains(name))
    })
}

/// Where a source file's test module begins: a private module, or a crate-visible one named
/// `tests` that other files' cases reach. A crate-visible module of another name holds product
/// text and is no marker.
const TEST_MODULE_MARKERS: [&str; 2] = [
    "\n#[cfg(test)]\nmod ",
    "\n#[cfg(test)]\npub(crate) mod tests {",
];

/// What a source file tells a person: its strings, and its `///` lines where they become help.
/// The file's test module is left out, since a test runs processes of its own (`kill -0` asks
/// whether one lives) and tells nobody anything; so is every other comment line.
fn product_part(source: &str) -> String {
    let end = TEST_MODULE_MARKERS
        .iter()
        .filter_map(|marker| source.find(marker))
        .min()
        .unwrap_or(source.len());
    let product = &source[..end];
    let help = makes_help(product);
    product
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            !line.starts_with("//") || (help && line.starts_with("///"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The texts under scan: the crates' sources outside their `tests` folders, and the guides under
/// `docs`. Limits: the scan stops at a source file's test module (either marker above), so a text
/// after that module is not read. It reads every guide except the conformance document, which lists the words of a
/// source check and gives no person an instruction.
fn texts() -> Vec<(PathBuf, String)> {
    let mut sources = Vec::new();
    files(&repository().join("crates"), &["rs"], &mut sources);
    let mut guides = Vec::new();
    files(&repository().join("docs"), &["md"], &mut guides);
    let in_folder = |path: &Path, folder: &str| {
        path.components()
            .any(|component| component.as_os_str() == folder)
    };
    let sources = sources
        .into_iter()
        .filter(|path| !in_folder(path, "tests"))
        .filter_map(|path| {
            let text = product_part(&std::fs::read_to_string(&path).ok()?);
            Some((path, text))
        });
    let guides = guides
        .into_iter()
        .filter(|path| !in_folder(path, "conformance"))
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            Some((path, text))
        });
    sources.chain(guides).collect()
}

/// The words after `prefix` in `text`: the letters and hyphens that follow it.
fn words_after<'a>(text: &'a str, prefix: &str) -> Vec<&'a str> {
    text.match_indices(prefix)
        .map(|(at, _)| {
            let rest = &text[at + prefix.len()..];
            let end = rest
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .collect()
}

/// A text that tells a person to run `kr host <word>` names a command the program has: a command
/// that is not there yet is not named, and one that was taken out is not named after it.
#[test]
fn every_kr_host_command_a_text_names_exists() {
    let cli = kr_cli::cli::Cli::command();
    let host = cli.find_subcommand("host").expect("kr has `host`");
    let known: Vec<&str> = host
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect();
    assert!(
        known.contains(&"stop"),
        "kr host stop is a command: {known:?}"
    );
    assert!(
        known.contains(&"restart"),
        "kr host restart is a command: {known:?}"
    );
    let mut unknown = Vec::new();
    for (path, text) in texts() {
        for word in words_after(&text, "kr host ") {
            if !word.is_empty()
                && word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_ascii_lowercase())
                && !known.contains(&word)
            {
                unknown.push(format!("{}: kr host {word}", path.display()));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "texts name a kr host command the program does not have:\n{}",
        unknown.join("\n")
    );
}

/// A text that tells a person to end a process by force says `kill -KILL`, or `taskkill /F`: a
/// plain `kill` is a request that a daemon in the middle of a write does not obey.
#[test]
fn every_kill_a_text_gives_is_the_forced_one() {
    let mut plain = Vec::new();
    for (path, text) in texts() {
        for signal in words_after(&text, "kill -") {
            if signal != "KILL" && signal != "9" {
                plain.push(format!("{}: kill -{signal}", path.display()));
            }
        }
        for (at, _) in text.match_indices("taskkill") {
            let tail: String = text[at..].chars().take(14).collect();
            if !tail.contains("/F") {
                plain.push(format!("{}: {tail}", path.display()));
            }
        }
    }
    assert!(
        plain.is_empty(),
        "texts give a kill that is not the forced one:\n{}",
        plain.join("\n")
    );
}

/// A source whose test module is private: its product text is read, and nothing from `mod ` on.
#[test]
fn a_private_test_module_ends_the_product_part() {
    let source = "const A: &str = \"kr host stop\";\n#[cfg(test)]\nmod tests {\n    const B: &str = \"taskkill\";\n}\n";
    let part = product_part(source);
    assert!(part.contains("kr host stop"), "{part}");
    assert!(!part.contains("taskkill"), "{part}");
}

/// A source whose test module is crate-visible and named `tests`: the same cut.
#[test]
fn a_crate_visible_test_module_ends_the_product_part() {
    let source = "const A: &str = \"kr host stop\";\n#[cfg(test)]\npub(crate) mod tests {\n    const B: &str = \"taskkill\";\n}\n";
    let part = product_part(source);
    assert!(part.contains("kr host stop"), "{part}");
    assert!(!part.contains("taskkill"), "{part}");
}

/// The cut is at the earlier marker, whichever form comes first: what stands inside the first
/// module is not product text, and what stands inside the second is not either. A crate-visible
/// module of another name is product text that the scan keeps, even where its name begins with
/// `tests`.
#[test]
fn the_product_part_ends_at_the_earlier_marker_only() {
    let private_first = "const A: &str = \"first\";\n#[cfg(test)]\nmod tests {\n    const M: &str = \"between\";\n}\n#[cfg(test)]\npub(crate) mod tests {\n    const B: &str = \"second\";\n}\n";
    let part = product_part(private_first);
    assert!(part.contains("first"), "{part}");
    assert!(
        !part.contains("between") && !part.contains("second"),
        "{part}"
    );

    let visible_first = "const A: &str = \"first\";\n#[cfg(test)]\npub(crate) mod tests {\n    const M: &str = \"between\";\n}\n#[cfg(test)]\nmod more {\n    const B: &str = \"second\";\n}\n";
    let part = product_part(visible_first);
    assert!(part.contains("first"), "{part}");
    assert!(
        !part.contains("between") && !part.contains("second"),
        "{part}"
    );

    for name in ["fixtures", "tests_more"] {
        let other_name = format!(
            "const A: &str = \"first\";\n#[cfg(test)]\npub(crate) mod {name} {{\n}}\nconst B: &str = \"second\";\n"
        );
        let part = product_part(&other_name);
        assert!(
            part.contains("first") && part.contains("second"),
            "{name}: {part}"
        );
    }
}
