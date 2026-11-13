//! The environment of every program the broker starts, built from a fixed table and from nothing
//! of the caller's environment.
//!
//! Git reads a great many variables, and every one of them that a caller can set is a way to point
//! Git at a program, a configuration file, a repository, a proxy or a log. A list of variables to
//! remove would miss the next one, so this module goes the other way: the block holds the
//! variables of its fixed table and no others. No function here reads the process's own environment, and
//! nothing in a request can add a variable.
//!
//! The module is pure: the system's own paths, the installation's folders, the invocation's private
//! root and the repository's paths are inputs, so the table is held to its values on every
//! platform. Paths are Windows paths, written with backslashes.

use std::fmt;

/// Which child the block is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An operation's Git: it works in one repository, which the block names.
    Operation,
    /// A configuration or attribute reader: it finds the repository from its directory, so the
    /// block names no repository, and it still carries the ceiling above the tree.
    ConfigRead,
    /// One of the broker's own readers of the repository's objects (`ls-tree`, `cat-file`): the
    /// block names the repository as it does for an operation.
    Reader,
    /// A program of the proof, which runs in no repository.
    Proof,
}

/// The folders that do not depend on the repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootPaths {
    /// The system's own Windows directory, as the platform reports it (not the caller's
    /// `SystemRoot`).
    pub system: String,
    /// The installation's own folder for the boundary: it holds the empty global configuration.
    pub boundary: String,
    /// The invocation's private root: `tmp\` and `home\` lie under it.
    pub private_root: String,
}

/// The repository's paths, as the broker resolved them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreePaths {
    /// The working tree.
    pub tree: String,
    /// The folder that holds the working tree.
    pub parent: String,
}

/// The Git installation the policy was written for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedGit {
    /// Where Git is installed.
    pub dir: String,
}

/// Why a block could not be built.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvError {
    /// The kind of child works in a repository and no repository was given.
    #[error("the {0:?} block needs the repository's paths")]
    NoTree(Kind),
    /// A path is empty or holds a NUL, which no environment value can.
    // text: env-1
    #[error("the {0} path is not usable")]
    BadPath(&'static str),
}

/// What a variable's value comes from.
#[derive(Clone, Copy, Debug)]
enum Value {
    /// The same text for every child.
    Literal(&'static str),
    /// The system's Windows directory.
    SystemRoot,
    /// The drive that holds it.
    SystemDrive,
    /// Git's own program folder, then the system's.
    Path,
    /// Where Git finds its own programs.
    GitExecPath,
    /// The invocation's temporary folder.
    PrivateTmp,
    /// The invocation's home folder.
    PrivateHome,
    /// The repository's `.git` folder.
    TreeGit,
    /// The repository's working tree.
    TreeWork,
    /// The folder above the working tree.
    TreeParent,
    /// The installation's empty global configuration.
    BoundaryConfig,
}

/// Which children carry a variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// Every child.
    All,
    /// Children that work in or beside a repository.
    Tree,
    /// Git in an operation, and the readers of the repository's objects.
    OperationTree,
}

/// Every variable a child gets, with where its value comes from. Nothing else is ever passed.
const TABLE: &[(&str, Value, Scope)] = &[
    ("SystemRoot", Value::SystemRoot, Scope::All),
    ("windir", Value::SystemRoot, Scope::All),
    ("SystemDrive", Value::SystemDrive, Scope::All),
    ("PATH", Value::Path, Scope::All),
    ("GIT_EXEC_PATH", Value::GitExecPath, Scope::All),
    ("TMP", Value::PrivateTmp, Scope::All),
    ("TEMP", Value::PrivateTmp, Scope::All),
    ("TMPDIR", Value::PrivateTmp, Scope::All),
    ("HOME", Value::PrivateHome, Scope::All),
    ("GIT_DIR", Value::TreeGit, Scope::OperationTree),
    ("GIT_WORK_TREE", Value::TreeWork, Scope::OperationTree),
    ("GIT_COMMON_DIR", Value::TreeGit, Scope::OperationTree),
    ("GIT_CEILING_DIRECTORIES", Value::TreeParent, Scope::Tree),
    ("GIT_CONFIG_NOSYSTEM", Value::Literal("1"), Scope::All),
    ("GIT_CONFIG_GLOBAL", Value::BoundaryConfig, Scope::All),
    ("GIT_TERMINAL_PROMPT", Value::Literal("0"), Scope::All),
    ("GIT_NO_LAZY_FETCH", Value::Literal("1"), Scope::All),
    ("GIT_PROTOCOL_FROM_USER", Value::Literal("0"), Scope::All),
    ("GIT_NO_REPLACE_OBJECTS", Value::Literal("1"), Scope::All),
    ("GIT_ATTR_NOSYSTEM", Value::Literal("1"), Scope::All),
    ("GIT_OPTIONAL_LOCKS", Value::Literal("0"), Scope::All),
    // An empty value, not a missing one: no protocol is allowed, whatever the configuration says.
    ("GIT_ALLOW_PROTOCOL", Value::Literal(""), Scope::All),
    ("GIT_PAGER", Value::Literal("cat"), Scope::All),
    ("GIT_EDITOR", Value::Literal("false"), Scope::All),
    ("GIT_SEQUENCE_EDITOR", Value::Literal("false"), Scope::All),
    ("LC_ALL", Value::Literal("C"), Scope::All),
];

/// The names of the variables a block can hold, for the cases that compare a child's environment
/// with the table.
#[must_use]
pub fn names() -> Vec<&'static str> {
    TABLE.iter().map(|entry| entry.0).collect()
}

/// An environment block in the form the platform wants: `NAME=value` entries, each ended by a NUL,
/// sorted by name without regard to case, and a final NUL.
#[derive(Clone, PartialEq, Eq)]
pub struct EnvBlock(Vec<u16>);

impl fmt::Debug for EnvBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.pairs()).finish()
    }
}

impl EnvBlock {
    /// The block's code units, with the double NUL at its end.
    #[must_use]
    pub fn units(&self) -> &[u16] {
        &self.0
    }

    /// The name and value of each entry, in the block's order.
    #[must_use]
    pub fn pairs(&self) -> Vec<(String, String)> {
        #[expect(
            clippy::disallowed_methods,
            reason = "an entry of the block in hand with no `=` has no name and no value and is left out; the block is split here and no read of the machine fails into it"
        )]
        let pairs = self
            .0
            .split(|unit| *unit == 0)
            .take_while(|entry| !entry.is_empty())
            .filter_map(|entry| {
                let text = String::from_utf16_lossy(entry);
                text.split_once('=')
                    .map(|(name, value)| (name.to_owned(), value.to_owned()))
            })
            .collect();
        pairs
    }

    pub(crate) fn from_pairs(mut pairs: Vec<(&'static str, String)>) -> EnvBlock {
        pairs.sort_by_key(|pair| pair.0.to_uppercase());
        let mut block = Vec::new();
        for (name, value) in pairs {
            block.extend(format!("{name}={value}").encode_utf16());
            block.push(0);
        }
        block.push(0);
        EnvBlock(block)
    }
}

fn joined(base: &str, leaf: &str) -> String {
    format!("{}\\{leaf}", base.trim_end_matches('\\'))
}

fn usable(what: &'static str, path: &str) -> Result<(), EnvError> {
    if path.is_empty() || path.contains('\0') {
        Err(EnvError::BadPath(what))
    } else {
        Ok(())
    }
}

/// Builds the block for a child.
///
/// `tree` is required for every kind but [`Kind::Proof`], which ignores it.
///
/// # Errors
///
/// Returns an error when a kind that works in a repository has none, or when a path is empty or
/// holds a NUL.
pub fn build_env(
    kind: Kind,
    root: &RootPaths,
    tree: Option<&TreePaths>,
    git: &QualifiedGit,
) -> Result<EnvBlock, EnvError> {
    let tree = match kind {
        Kind::Operation | Kind::ConfigRead | Kind::Reader => {
            Some(tree.ok_or(EnvError::NoTree(kind))?)
        }
        Kind::Proof => None,
    };
    usable("system", &root.system)?;
    usable("boundary", &root.boundary)?;
    usable("private root", &root.private_root)?;
    usable("Git", &git.dir)?;
    if let Some(tree) = tree {
        usable("tree", &tree.tree)?;
        usable("tree parent", &tree.parent)?;
    }
    let mut pairs = Vec::new();
    for (name, value, scope) in TABLE {
        let wanted = match scope {
            Scope::All => true,
            Scope::Tree => tree.is_some(),
            Scope::OperationTree => matches!(kind, Kind::Operation | Kind::Reader),
        };
        if !wanted {
            continue;
        }
        let text = match value {
            Value::Literal(text) => (*text).to_owned(),
            Value::SystemRoot => root.system.clone(),
            Value::SystemDrive => root.system.chars().take(2).collect(),
            Value::Path => format!(
                "{};{}",
                joined(&joined(&git.dir, "mingw64"), "bin"),
                joined(&root.system, "System32")
            ),
            Value::GitExecPath => {
                joined(&joined(&joined(&git.dir, "mingw64"), "libexec"), "git-core")
            }
            Value::PrivateTmp => joined(&root.private_root, "tmp"),
            Value::PrivateHome => joined(&root.private_root, "home"),
            Value::TreeGit => tree.map_or_else(String::new, |tree| joined(&tree.tree, ".git")),
            Value::TreeWork => tree.map_or_else(String::new, |tree| tree.tree.clone()),
            Value::TreeParent => tree.map_or_else(String::new, |tree| tree.parent.clone()),
            Value::BoundaryConfig => joined(&joined(&root.boundary, "git"), "config"),
        };
        pairs.push((*name, text));
    }
    Ok(EnvBlock::from_pairs(pairs))
}
