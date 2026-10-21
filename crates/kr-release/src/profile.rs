//! How a host starts each shell, and where it puts the package's marked entry.
//!
//! A release says it once, from the host's own tables: the arguments a shell is started with in
//! each mode, and the startup files that hold the entry. The arguments name no option that skips or
//! replaces a startup file of the person's, so every startup file runs in the order the shell reads
//! them and the package's entry runs among them; the entries are put in files the shell reads
//! itself. A person who moves a startup directory (`ZDOTDIR`, `XDG_CONFIG_HOME`) moves the entry
//! with it, which the location says in the shell's own words.

use std::path::{Path, PathBuf};

use kr_protocol::update::{EntryPlacement, LaunchMode, ProfileEntry, ProfileLaunch};
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{ShellPackage, StartupMode};
use kr_shell_integration::host::startup::{HomeLayout, Placement, StartupTarget};

use crate::refusal::{Refusal, Result, refuse};

/// The directories a person can move, as the sentinel layouts name them.
const HOME: &str = "/kr-release-home";
const ZDOTDIR: &str = "/kr-release-zdotdir";
const XDG_CONFIG_HOME: &str = "/kr-release-xdg";

/// What a package states about how a host starts it.
///
/// # Errors
///
/// Returns a refusal for a shell that has no startup file this tool can state, and for a startup
/// argument that skips or replaces a startup file of the person's.
pub fn profile_order(package: &ShellPackage) -> Result<Vec<ProfileLaunch>> {
    let kind = package.kind();
    let entries = entries(kind)?;
    let mut launches = Vec::new();
    for (mode, startup) in [
        (LaunchMode::Login, StartupMode::Login),
        (LaunchMode::Interactive, StartupMode::Interactive),
    ] {
        let arguments = package.arguments(startup);
        if let Some(skipping) = arguments.iter().find(|argument| skips_startup(argument)) {
            refuse!(
                "{} is started with `{skipping}`, which skips or replaces a startup file of the \
                 person's",
                kind.as_str()
            );
        }
        launches.push(ProfileLaunch {
            mode,
            arguments,
            entries: entries
                .iter()
                .filter(|(_, reads)| match mode {
                    LaunchMode::Login => true,
                    LaunchMode::Interactive => *reads == Reads::Always,
                })
                .map(|(entry, _)| entry.clone())
                .collect(),
        });
    }
    Ok(launches)
}

/// Whether a startup file is read by every interactive shell or only by a login one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
    Always,
    LoginOnly,
}

/// An argument that makes a shell skip or replace a startup file of the person's.
fn skips_startup(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase();
    [
        "-f",
        "--norc",
        "--noprofile",
        "--no-config",
        "--rcfile",
        "--init-file",
        "-noprofile",
    ]
    .iter()
    .any(|skipping| lowered == *skipping || lowered.starts_with(&format!("{skipping}=")))
}

fn entries(kind: ShellKind) -> Result<Vec<(ProfileEntry, Reads)>> {
    let plain = HomeLayout {
        home: PathBuf::from(HOME),
        zdotdir: None,
        xdg_config_home: None,
        powershell: None,
    };
    let moved = HomeLayout {
        zdotdir: Some(PathBuf::from(ZDOTDIR)),
        xdg_config_home: Some(PathBuf::from(XDG_CONFIG_HOME)),
        ..plain.clone()
    };
    match kind {
        ShellKind::Zsh | ShellKind::Fish => {
            let (here, there) = (plain.targets(kind), moved.targets(kind));
            if here.len() != 1 || there.len() != 1 {
                refuse!(
                    "{} has {} startup files for the host, and this tool states one",
                    kind.as_str(),
                    here.len()
                );
            }
            Ok(vec![(
                entry(&here[0], &location_moving(&here[0], &there[0])?),
                Reads::Always,
            )])
        }
        ShellKind::Bash => {
            let targets = plain.targets(kind);
            let [interactive, login] = targets.as_slice() else {
                refuse!(
                    "bash has {} startup files for the host, not two",
                    targets.len()
                );
            };
            Ok(vec![
                (
                    entry(interactive, &symbolic(&interactive.path)?),
                    Reads::Always,
                ),
                (
                    entry(
                        login,
                        "the first of $HOME/.bash_profile, $HOME/.bash_login and $HOME/.profile \
                         that exists, else $HOME/.bash_profile",
                    ),
                    Reads::LoginOnly,
                ),
            ])
        }
        ShellKind::PowerShell => refuse!(
            "a PowerShell package states its profiles from the shell that qualified it, which \
             this tool does not start"
        ),
    }
}

fn entry(target: &StartupTarget, location: &str) -> ProfileEntry {
    let (begin, end) = target.placement.markers();
    ProfileEntry {
        location: location.to_owned(),
        placement: match target.placement {
            Placement::End => EntryPlacement::End,
            Placement::AfterPrologue { .. } => EntryPlacement::AfterPrologue,
            Placement::Last { .. } => EntryPlacement::Last,
        },
        begin: begin.to_owned(),
        end: end.to_owned(),
    }
}

/// A path under a sentinel directory, as the variable that names the directory.
fn symbolic(path: &Path) -> Result<String> {
    for (sentinel, variable) in [
        (ZDOTDIR, "$ZDOTDIR"),
        (XDG_CONFIG_HOME, "$XDG_CONFIG_HOME"),
        (HOME, "$HOME"),
    ] {
        if let Ok(rest) = path.strip_prefix(sentinel) {
            let rest = rest.to_string_lossy();
            return Ok(if rest.is_empty() {
                variable.to_owned()
            } else {
                format!("{variable}/{rest}")
            });
        }
    }
    Err(Refusal(format!(
        "{} is under none of the directories a person can move",
        path.display()
    )))
}

/// Where a file is for a person who has not moved a directory, and for one who has, in the shell's
/// own words for a default: `${ZDOTDIR:-$HOME}/.zshrc`.
fn location_moving(here: &StartupTarget, there: &StartupTarget) -> Result<String> {
    let (here, there) = (symbolic(&here.path)?, symbolic(&there.path)?);
    if here == there {
        return Ok(here);
    }
    let here_parts: Vec<&str> = here.split('/').collect();
    let there_parts: Vec<&str> = there.split('/').collect();
    let mut common = 0;
    while common < here_parts.len().min(there_parts.len())
        && here_parts[here_parts.len() - 1 - common] == there_parts[there_parts.len() - 1 - common]
    {
        common += 1;
    }
    let tail = here_parts[here_parts.len() - common..].join("/");
    let head_here = here_parts[..here_parts.len() - common].join("/");
    let head_there = there_parts[..there_parts.len() - common].join("/");
    if !head_there.starts_with('$') || head_there.contains('/') {
        refuse!("`{there}` is not a moved directory and a file in it");
    }
    Ok(format!("${{{}:-{head_here}}}/{tail}", &head_there[1..]))
}
