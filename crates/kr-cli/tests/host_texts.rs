//! What the program and its guides tell a person to type: each `kr host` command a text names is
//! one the program has, and each command that ends a process by force is the forced one.
//!
//! The scan reads the product's own strings and the guides. It does not judge whether a remedy
//! works; a remedy's accuracy is read in review.

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

/// The texts under scan: the crates' sources and the guides.
fn texts() -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    files(&repository().join("crates"), &["rs"], &mut paths);
    files(&repository().join("docs"), &["md"], &mut paths);
    paths
        .into_iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(&path).ok()?;
            Some((path, text))
        })
        .collect()
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
