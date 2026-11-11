//! The command-scope settings every command runs with, and the one rule for line endings.
//!
//! The repository's own file is read and refused where it names an address, a program or another
//! location; the settings here are what Git is told on the command line besides. A value on the
//! command line does not undo what the file says, which is why the file is classified first. Every
//! setting is set whether or not the compiled default would do, so that a Git with another default
//! behaves the same.

use super::{OperationLine, Writes};
use crate::frame::invocation::{Identity, LineEndings, RefusedKind};
use crate::refusal::Refusal;
use crate::repository::config::{AutoCrlf, ConfigFacts};

/// One setting: a key and the value given with `-c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    /// The key.
    pub key: &'static str,
    /// The value, which may be empty.
    pub value: &'static str,
}

const fn set(key: &'static str, value: &'static str) -> Setting {
    Setting { key, value }
}

/// The settings whose value does not depend on the tree, the person or the installation.
pub const FIXED_SETTINGS: &[Setting] = &[
    // No credential helper, and none is added later.
    set("credential.helper", ""),
    set("credential.useHttpPath", "false"),
    // No file-system monitor. The empty value stays: older Git reads a non-empty `false` as the
    // path of a hook, and newer Git reads the empty value as false.
    set("core.fsmonitor", ""),
    set("core.fsmonitorHookVersion", ""),
    set("core.untrackedCache", "false"),
    // No pager, editor, proxy, ssh, external program or file outside the repository.
    set("core.pager", "cat"),
    set("core.editor", "false"),
    set("sequence.editor", "false"),
    set("core.askPass", ""),
    set("core.gitProxy", ""),
    set("core.sshCommand", ""),
    set("core.alternateRefsCommand", ""),
    set("core.alternateRefsPrefixes", ""),
    set("core.attributesFile", ""),
    set("core.excludesFile", ""),
    set("diff.external", ""),
    set("uploadpack.packObjectsHook", ""),
    // No signature program.
    set("gpg.program", "false"),
    set("gpg.openpgp.program", "false"),
    set("gpg.x509.program", "false"),
    set("gpg.ssh.program", "false"),
    set("commit.gpgSign", "false"),
    set("tag.gpgSign", "false"),
    set("log.showSignature", "false"),
    // No maintenance.
    set("gc.auto", "0"),
    set("gc.autoDetach", "false"),
    set("maintenance.auto", "false"),
    set("maintenance.autoDetach", "false"),
    // No recursion into submodules.
    set("submodule.recurse", "false"),
    set("fetch.recurseSubmodules", "no"),
    set("push.recurseSubmodules", "no"),
    set("diff.ignoreSubmodules", "all"),
    set("status.submoduleSummary", "false"),
    // No bundle address and no transport.
    set("transfer.bundleURI", "false"),
    set("protocol.allow", "never"),
    // What the compiled defaults are not trusted to be.
    set("core.protectNTFS", "true"),
    set("log.mailmap", "false"),
    set("core.symlinks", "false"),
    // No bare repository found by looking.
    set("safe.bareRepository", "explicit"),
];

/// The settings whose value the installation, the tree or the request decides.
pub const FOLDER_SETTINGS: [&str; 2] = ["core.hooksPath", "init.templateDir"];

/// The folder of the installation that holds the empty hooks folder, below the boundary's own.
pub const HOOKS_FOLDER: &str = "git\\hooks";
/// The folder of the installation that holds the empty template folder, below the boundary's own.
pub const TEMPLATE_FOLDER: &str = "git\\template";

/// The host's `unknown` line endings, a writing command and no value in the held configuration.
pub const RULE_LINE_ENDINGS: &str = "operation-line-endings";
/// A tree path that cannot be the value of `safe.directory`.
pub const RULE_SAFE_DIRECTORY: &str = "operation-safe-directory";

/// What the settings that are not fixed are made from.
#[derive(Clone, Copy, Debug)]
pub struct SettingsInput<'a> {
    /// The installation's folder for the boundary accounts; the hooks and template folders lie
    /// below it.
    pub boundary: &'a str,
    /// The path of the granted tree, in the spelling Git compares. Never `*`.
    pub tree: &'a str,
    /// The name and address a commit and a reflog entry carry.
    pub identity: &'a Identity,
    /// The host's own value of `core.autocrlf`.
    pub line_endings: LineEndings,
}

/// The one value of `core.autocrlf` a command runs with, and `None` where none is set.
///
/// The held configuration's own value decides first, as written, even when the host says
/// `unknown`. With none, the host's value counts if it is `true`, `false` or `input`; `unset`
/// sets nothing; `unknown` is never handed to Git, so a command that writes is refused and a
/// command that only reads runs with no setting.
///
/// # Errors
///
/// Returns a refusal when the host says `unknown`, the held configuration has no value and the
/// command writes.
pub fn effective_autocrlf(
    held: Option<AutoCrlf>,
    host: LineEndings,
    writes: Writes,
) -> Result<Option<AutoCrlf>, Refusal> {
    if held.is_some() {
        return Ok(held);
    }
    match (host, writes) {
        (LineEndings::True, _) => Ok(Some(AutoCrlf::True)),
        (LineEndings::False, _) => Ok(Some(AutoCrlf::False)),
        (LineEndings::Input, _) => Ok(Some(AutoCrlf::Input)),
        (LineEndings::Unset | LineEndings::Unknown, Writes::No)
        | (LineEndings::Unset, Writes::Yes) => Ok(None),
        (LineEndings::Unknown, Writes::Yes) => Err(Refusal::new(
            RefusedKind::Operation,
            RULE_LINE_ENDINGS,
            "the host could not tell how line endings are set, and the repository sets none; \
             a command that writes needs one",
        )),
    }
}

/// How `core.autocrlf` is written.
#[must_use]
pub const fn autocrlf_text(value: AutoCrlf) -> &'static str {
    match value {
        AutoCrlf::True => "true",
        AutoCrlf::False => "false",
        AutoCrlf::Input => "input",
    }
}

fn refuse_tree() -> Refusal {
    Refusal::new(
        RefusedKind::Operation,
        RULE_SAFE_DIRECTORY,
        "the tree's path cannot be the one directory Git is told is safe",
    )
}

/// The whole argument list of a launch: Git's global options, every setting as `-c key=value`,
/// and the line [`super::parse_operation`] built.
///
/// # Errors
///
/// Returns a refusal when the line endings rule refuses, or when the tree's path is empty, is `*`
/// or holds a control character.
pub fn command_arguments(
    input: &SettingsInput<'_>,
    facts: &ConfigFacts,
    line: &OperationLine,
) -> Result<Vec<String>, Refusal> {
    if input.tree.is_empty()
        || input.tree == "*"
        || input.tree.chars().any(super::grammar::is_control)
    {
        return Err(refuse_tree());
    }
    let crlf = effective_autocrlf(facts.autocrlf_local, input.line_endings, line.writes)?;
    let mut settings: Vec<(String, String)> = FIXED_SETTINGS
        .iter()
        .map(|setting| (setting.key.to_owned(), setting.value.to_owned()))
        .collect();
    settings.push((
        FOLDER_SETTINGS[0].to_owned(),
        format!("{}\\{HOOKS_FOLDER}", input.boundary),
    ));
    settings.push((
        FOLDER_SETTINGS[1].to_owned(),
        format!("{}\\{TEMPLATE_FOLDER}", input.boundary),
    ));
    if let Some(value) = crlf {
        settings.push(("core.autocrlf".to_owned(), autocrlf_text(value).to_owned()));
    }
    settings.push(("safe.directory".to_owned(), input.tree.to_owned()));
    settings.push(("user.name".to_owned(), input.identity.name.clone()));
    settings.push(("user.email".to_owned(), input.identity.email.clone()));

    let mut arguments = vec!["--no-pager".to_owned(), "--literal-pathspecs".to_owned()];
    for (key, value) in settings {
        arguments.push("-c".to_owned());
        arguments.push(format!("{key}={value}"));
    }
    arguments.extend(line.argv.iter().cloned());
    Ok(arguments)
}
