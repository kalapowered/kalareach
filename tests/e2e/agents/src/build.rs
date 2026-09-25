//! The build under test, as the harness describes it, and the inputs a part reads.
//!
//! The harness takes each build's entry from the plugin repository's build list, makes its paths
//! absolute for the machine it runs on, checks the pinned file's digest, and writes the result to
//! the file [`crate::BUILD_VARIABLE`] names. Nothing here fetches or installs a build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{BUILD_VARIABLE, GENERATION_VARIABLE, REQUIRE_VARIABLE, RESULT_VARIABLE};

/// One input typed at the agent and the text its screen shows once the input arrived.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    /// What is typed, as text; escape sequences are written as JSON escapes.
    pub input: String,
    /// Text the agent's screen shows once the input arrived, and did not show before it.
    pub shows: String,
}

/// How the agent reaches the composer a person types a prompt into, without an account.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Composer {
    /// Inputs typed first, in order, each waited on by its screen text, such as accepting a
    /// folder-trust dialog.
    pub prepare: Vec<Keys>,
}

/// A process the agent's terminal route starts first, in a session of its own.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Its arguments after the command, with `{port}` where the run's loopback port goes.
    pub arguments: Vec<String>,
    /// Text its terminal shows once it serves.
    pub ready: String,
}

/// A newer build of the same application, installed beside the pinned one, for the upgrade case.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Newer {
    /// The version it is.
    pub version: String,
    /// Where it is installed: an absolute directory on the internal disk.
    pub prefix: PathBuf,
    /// The file the build's digest names, relative to the prefix: for a native build, the
    /// executable its processes map.
    pub pinned: String,
    /// That file's SHA-256, lower-case hexadecimal.
    pub sha256: String,
    /// Text its first screen shows.
    pub ready: String,
}

/// The build under test.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// The connector package qualified against this build, as `publisher/plugin`.
    pub package: String,
    /// The actions the package's manifest registers, by identifier.
    #[serde(default)]
    pub actions: Vec<String>,
    /// The application, as the record names it.
    pub application: String,
    /// The version the package's table is pinned to.
    pub version: String,
    /// Where the build is installed: an absolute directory on the internal disk.
    pub prefix: PathBuf,
    /// The file whose SHA-256 the qualification pins, relative to the prefix: the executable of a
    /// native build, the script of one a runtime runs, the wheel of one a package manager installs.
    pub pinned: String,
    /// That file's SHA-256, lower-case hexadecimal, as the harness checked it.
    pub sha256: String,
    /// The command a person types, found through `bin` under the prefix.
    pub command: String,
    /// The arguments typed after it, with `{port}` where a server's loopback port goes.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// The executables of the runtimes the build needs, such as `node`: each is linked into a
    /// directory of the run's own that the session searches after the build's `bin`, so the
    /// session's PATH names no directory another installation shares.
    #[serde(default)]
    pub runtime: Vec<PathBuf>,
    /// Variables the build is started with: its updater and telemetry switches.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Files written into the agent's home before it starts, by path relative to the home: the
    /// state a person's installation has after the vendor's own first-run steps, and never an
    /// account.
    #[serde(default)]
    pub home: BTreeMap<String, String>,
    /// Text the agent's first screen shows.
    pub ready: String,
    /// One input that changes the first screen and commits nothing.
    pub harmless: Keys,
    /// How it reaches its composer without an account, where it has one without one.
    #[serde(default)]
    pub composer: Option<Composer>,
    /// A server the terminal route starts first, where it has one.
    #[serde(default)]
    pub server: Option<Server>,
    /// Where the vendor keeps a conversation's transcript, relative to the home, with
    /// `{cwd_slug}` for the working directory with each `/` as `-` and `{session}` for its
    /// identifier.
    pub transcript: String,
    /// A newer build for the upgrade case, where one is named.
    #[serde(default)]
    pub newer: Option<Newer>,
}

impl Build {
    /// The pinned file, absolute.
    #[must_use]
    pub fn pinned_file(&self) -> PathBuf {
        self.prefix.join(&self.pinned)
    }

    /// The line typed at the prompt to start the agent, with `port` in place of `{port}`.
    #[must_use]
    pub fn command_line(&self, port: u16) -> String {
        let mut words = vec![self.command.clone()];
        words.extend(
            self.arguments
                .iter()
                .map(|argument| quote(&argument.replace("{port}", &port.to_string()))),
        );
        words.join(" ")
    }
}

/// What a part reads before it starts anything.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// The build under test.
    pub build: Build,
    /// The signed catalogue generation the package is installed from.
    pub generation: PathBuf,
    /// The file the part appends its outcome to.
    pub result: PathBuf,
}

impl Inputs {
    /// The inputs this run was given, or nothing when it was given none.
    ///
    /// # Panics
    ///
    /// Panics when [`REQUIRE_VARIABLE`] promised the inputs and one is missing, and when the build
    /// file is not one: a part that skipped instead would report nothing for a build it was asked
    /// to run.
    #[must_use]
    pub fn from_environment(part: &str) -> Option<Self> {
        let named = |variable: &str| {
            std::env::var_os(variable)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        let (Some(build), Some(generation), Some(result)) = (
            named(BUILD_VARIABLE),
            named(GENERATION_VARIABLE),
            named(RESULT_VARIABLE),
        ) else {
            let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
            assert!(
                !required,
                "{REQUIRE_VARIABLE}=1 and {BUILD_VARIABLE}, {GENERATION_VARIABLE} or \
                 {RESULT_VARIABLE} names nothing, so part {part} could not run"
            );
            eprintln!(
                "skipping: part {part}: {BUILD_VARIABLE}, {GENERATION_VARIABLE} and \
                 {RESULT_VARIABLE} name no build to run"
            );
            return None;
        };
        let build = read_build(&build);
        Some(Self {
            build,
            generation,
            result,
        })
    }
}

fn read_build(path: &Path) -> Build {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("the build file {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("the build file {}: {error}", path.display()))
}

/// Quotes one word for a POSIX shell line.
#[must_use]
pub fn quote(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:=@+,".contains(&byte))
    {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}
