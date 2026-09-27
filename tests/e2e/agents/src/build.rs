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
    /// A path the server answers with status 200 once it serves requests, which can be later than
    /// the text says so.
    #[serde(default)]
    pub health: Option<String>,
}

/// Whose home an agent runs with in the parts that need its login.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountHome {
    /// The run's own, so none of the person's agent directories changes: the login is a keychain
    /// item the run's home may search, or a variable.
    Run,
    /// The person's, where the agent keeps its login in files of its own.
    Person,
}

/// A permission dialog the agent raises before it runs a command, and the keys that answer it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// Text the dialog shows.
    pub shows: String,
    /// What allows the command once.
    pub allow: String,
    /// What refuses it.
    pub deny: String,
}

/// A command that says whether a login holds without calling a model, and what its output holds
/// when it does.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// The arguments typed after the command.
    pub arguments: Vec<String>,
    /// Text the output holds, spaces aside, when the login holds.
    pub shows: String,
}

/// A directory of the run's own the agent keeps its configuration, history and conversations in,
/// where it runs with the person's home: the variable that names it, and the files its vendor's
/// first-run steps leave there.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDirectory {
    /// The variable the agent reads the directory from.
    pub variable: String,
    /// Files written into it before the agent starts, by path relative to it.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

/// How the parts that need the person's vendor login run the agent. Nothing here is a credential:
/// a login is named by its kind and where it lives, and a variable by its name.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// The login's kind, as the record names it, such as `vendor subscription login`.
    pub login: String,
    /// Where the login lives, by kind, such as `login keychain item`.
    pub stored: String,
    /// Whose home the agent runs with.
    pub home: AccountHome,
    /// Whether the login is an item of the person's login keychain: a run's home searches that
    /// keychain, borrowed, and the run never creates or deletes a keychain for it; and the agent's
    /// sessions run in the person's desktop, as a person's own do, since a headless session reads
    /// the keychain as one it may not ask to unlock.
    #[serde(default)]
    pub login_keychain: bool,
    /// The variable the login is, where it is one: the harness hands its value over on a pipe.
    #[serde(default)]
    pub variable: Option<String>,
    /// Arguments typed after the command in these parts, such as a model.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// The command that says whether the login holds, where the agent has one. Where it has none,
    /// a part learns it from whether the agent reaches its composer and from `signed_out`.
    #[serde(default)]
    pub status: Option<Status>,
    /// The command that says, without calling a model, that the agent loads no server of the
    /// person's own, and what its output holds when it loads none.
    #[serde(default)]
    pub isolated: Option<Status>,
    /// Where the agent keeps its configuration in these parts, where it is not the home.
    #[serde(default)]
    pub config_directory: Option<ConfigDirectory>,
    /// Variables the agent's session is given as they are, such as a switch that turns something
    /// of the person's off.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    /// The name of the login's keychain item, whose modification time says whether the agent
    /// rewrote it (a token refresh); its value is never read here.
    #[serde(default)]
    pub keychain_item: Option<String>,
    /// Files of the person's home, relative to it, that no part may change: a change stops the
    /// agent.
    #[serde(default)]
    pub guarded: Vec<String>,
    /// Files of the person's home that the person's own programs also write: a change that names
    /// the run's directory or the part's mark stops the agent, and any other is recorded.
    #[serde(default)]
    pub shared: Vec<String>,
    /// Text the agent shows when its login is missing, has expired or is refused.
    #[serde(default)]
    pub signed_out: Vec<String>,
    /// The budget these parts' turns are charged to: one per vendor login.
    pub budget: String,
    /// The most turns the budget allows.
    pub turns: u64,
    /// The agent's own directories in the person's home, relative to it, listed before and after
    /// each part that runs there.
    #[serde(default)]
    pub directories: Vec<String>,
    /// Whether the agent stops at the first part after which a file it had in those directories
    /// was rewritten rather than appended to.
    #[serde(default)]
    pub stop_on_rewrite: bool,
    /// Where the agent keeps its conversations, relative to its configuration directory where it
    /// has one, and to the home it runs with otherwise.
    pub conversations: String,
    /// What marks the line of a conversation file that holds a prompt the person sent.
    pub prompt_line: String,
    /// Text the agent's first screen shows with the login.
    pub ready: String,
    /// Inputs typed first, each waited on by its screen text, to reach the composer.
    #[serde(default)]
    pub prepare: Vec<Keys>,
    /// Text the screen shows while the composer waits for a prompt.
    pub composer: String,
    /// What submits a prompt typed in the composer.
    pub submit: String,
    /// What empties the composer without submitting it.
    pub clear: String,
    /// What marks the line of a conversation file that holds one of the agent's replies.
    pub reply_line: String,
    /// Text the agent's screen shows at the start of each of its replies.
    pub reply_mark: String,
    /// What marks the line of a conversation file that records the answer to a tool approval:
    /// the command's result, or its refusal.
    pub decision_line: String,
    /// Text the screen shows while a turn runs.
    pub busy: String,
    /// A slash command that calls no model and changes no conversation, and the text it shows.
    pub slash: Keys,
    /// What closes the slash command's screen.
    pub dismiss: String,
    /// The key that interrupts a running turn, and the text the agent shows once it stopped.
    pub interrupt: Keys,
    /// Whether a prompt entered while a turn runs steers that turn, rather than waiting for it.
    #[serde(default)]
    pub steers: bool,
    /// The dialog the agent raises before it runs a shell command.
    pub approval: Approval,
    /// The arguments that resume a saved conversation, with `{conversation}` for its identifier.
    pub resume: Vec<String>,
    /// How an image is given at the composer: `paste`, its absolute path as a terminal pastes it,
    /// or a template with `{path}`.
    pub image: String,
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

/// One action the package's manifest declares, as a part uses it: the declaration as the manifest
/// states it, read for its identifier, its effect, how it is carried out and its parameters.
#[derive(Clone, Debug, Deserialize)]
pub struct Action {
    /// The action's identifier.
    pub id: String,
    /// Its effect class, such as `observe` or `upstream.prompt`.
    pub effect: String,
    /// How it is carried out, with its `type`, such as `presentation`.
    pub implementation: serde_json::Value,
    /// Its parameter declarations, under `parameters`.
    #[serde(default)]
    pub parameters: serde_json::Value,
}

impl Action {
    /// Whether the host carries it out itself by redrawing the package's document: an
    /// observation.
    #[must_use]
    pub fn presentation(&self) -> bool {
        self.effect == "observe" && self.implementation["type"] == "presentation"
    }

    /// Whether it acts on the upstream agent.
    #[must_use]
    pub fn upstream(&self) -> bool {
        self.effect.starts_with("upstream.")
    }

    /// Parameters the declaration accepts: each text parameter `text`, each choice its first
    /// choice, so a refusal says something about the route and not about the parameters.
    #[must_use]
    pub fn well_formed(&self, text: &str) -> serde_json::Value {
        let mut parameters = serde_json::Map::new();
        for declared in self.parameters["parameters"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let Some(name) = declared["name"].as_str() else {
                continue;
            };
            let kind = &declared["kind"];
            match kind["type"].as_str() {
                Some("text") => {
                    parameters.insert(name.to_owned(), serde_json::json!(text));
                }
                Some("choice") => {
                    if let Some(first) = kind["choices"][0]["id"].as_str() {
                        parameters.insert(name.to_owned(), serde_json::json!(first));
                    }
                }
                _ => {}
            }
        }
        serde_json::Value::Object(parameters)
    }
}

/// How a launch of the build reaches its pinned file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Launch {
    /// The agent's own process, the shell's child, maps the pinned executable.
    Native,
    /// The agent's own process is a runtime that starts a process mapping the pinned executable.
    Child,
    /// The agent's own process is a runtime whose first argument is the pinned script.
    Script,
    /// The agent's own process is a runtime that loads the code installed from the pinned wheel,
    /// which the harness compares with the wheel, with the launcher that names that installation's
    /// interpreter.
    Wheel,
}

/// The build under test.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// The connector package qualified against this build, as `publisher/plugin`.
    pub package: String,
    /// The actions the package's manifest declares.
    #[serde(default)]
    pub actions: Vec<Action>,
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
    /// How a launch reaches the pinned file.
    pub launch: Launch,
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
    /// How the parts that need the person's vendor login run the agent, where the person approved
    /// one for it; why not, where not.
    #[serde(default)]
    pub account: Option<Account>,
    /// Why the parts that need a login do not run, where the build has no `account`.
    #[serde(default)]
    pub no_account: Option<String>,
    /// Why the upgrade part has no newer build, where the build has no `newer`.
    #[serde(default)]
    pub no_newer: Option<String>,
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
