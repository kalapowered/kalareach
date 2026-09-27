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
    /// What refuses the command, and nothing more: the agent keeps no rule from it.
    pub deny: String,
    /// What the dialog shows before a command on the command's own line, where it shows one, such
    /// as `$ `. The part answers a dialog only when one line of it is the part's command, whole,
    /// after this; and, where this is named, no other line starts with it and the line after the
    /// command's is blank, so a command that goes on to another line is not taken for the part's.
    #[serde(default)]
    pub command_line: Option<String>,
    /// Texts the agent's other permission dialogs show, such as for file edits, network access,
    /// further permissions or input to a running command: none is ever allowed, each is refused.
    #[serde(default)]
    pub others: Vec<String>,
    /// What refuses any of the agent's permission dialogs without the agent keeping a rule from
    /// it, where [`Approval::deny`] would not in every one of them; [`Approval::deny`] otherwise.
    #[serde(default)]
    pub refuse: Option<String>,
}

impl Approval {
    /// The key that refuses any dialog the part did not ask for.
    #[must_use]
    pub fn refusal(&self) -> &str {
        self.refuse.as_deref().unwrap_or(&self.deny)
    }

    /// Whether the dialog on `rows` asks to run `command` and nothing else, as
    /// [`Approval::command_line`] says the dialog shows a command; says why not otherwise.
    ///
    /// # Errors
    ///
    /// Returns what the dialog shows in place of the command alone.
    pub fn names_only(&self, rows: &[String], command: &str) -> Result<(), String> {
        let prefix = self.command_line.as_deref().unwrap_or("");
        let wanted = format!("{prefix}{command}");
        let at: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.trim() == wanted.trim())
            .map(|(index, _)| index)
            .collect();
        let [line] = at.as_slice() else {
            return Err(format!(
                "the dialog shows the part's command on {} lines of its own, not one",
                at.len()
            ));
        };
        if let Some(prefix) = &self.command_line {
            let others = rows
                .iter()
                .enumerate()
                .filter(|(index, row)| index != line && row.trim().starts_with(prefix.trim()))
                .count();
            if others > 0 {
                return Err(format!("the dialog shows {others} other command line(s)"));
            }
            if rows
                .get(line + 1)
                .is_some_and(|next| !next.trim().is_empty())
            {
                return Err("the command goes on past the part's command".to_owned());
            }
        }
        Ok(())
    }
}

/// A command the agent answers without calling a model, and what its answer must hold and must not
/// hold: whether its login holds, or that it loads nothing of the person's own.
///
/// Where the arguments hold `{stub}`, it is the address of a stub on this machine that stands in for
/// the vendor's model service: the command sends the agent's first request there, the stub keeps
/// only the names of the tools the request offers and answers it with an error, and those names,
/// one per line, are the answer. No model is called and no login is sent.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    /// The arguments typed after the command, before the account's switches.
    pub arguments: Vec<String>,
    /// Texts the answer holds, each of them, spaces aside.
    #[serde(default)]
    pub shows: Vec<String>,
    /// Lines the answer holds, each a whole line, with every run of spaces read as one space.
    #[serde(default)]
    pub lines: Vec<String>,
    /// Texts the answer must not hold, compared without regard to case; `{servers}` stands for
    /// each server the person's configuration names.
    #[serde(default)]
    pub lacks: Vec<String>,
    /// Where the answer is JSON: the one block of it the part accepts although it holds some of
    /// `lacks`, a file of the person's own the agent always reads.
    #[serde(default)]
    pub accepted: Option<Accepted>,
    /// Where the answer is JSON, [`Probe::shows`] is looked for only in its strings that begin
    /// with this: the block that states what the texts say.
    #[serde(default)]
    pub shows_within: Option<String>,
}

/// The one block of a JSON answer a probe accepts: exactly one of its strings begins with
/// `starts`, and that string holds the file `file` of the person's home, whole. Everything else in
/// the answer, and what that string holds besides the file, is still searched.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    /// What the block begins with.
    pub starts: String,
    /// The file it carries, relative to the person's home.
    pub file: String,
}

impl Probe {
    /// Whether the answer `text` holds each of [`Probe::shows`], spaces aside (only in the strings
    /// that begin with [`Probe::shows_within`], where it names them), each of [`Probe::lines`]
    /// whole, runs of spaces read as one, and none of [`Probe::lacks`], compared without regard to
    /// case, `{servers}` standing for each of `servers`. Where [`Probe::accepted`] names a block,
    /// exactly one string of the JSON answer begins with it and holds `accepted`, the person's file
    /// it carries, whole; that file's text is the only part of the answer not searched. Says only
    /// which text was found or missed, never the answer.
    ///
    /// # Errors
    ///
    /// Returns the first text the answer misses or holds against the probe.
    pub fn check(
        &self,
        text: &str,
        servers: &[String],
        accepted: Option<&str>,
    ) -> Result<(), String> {
        let squeeze = |text: &str| -> String {
            text.chars()
                .filter(|character| !character.is_whitespace())
                .collect()
        };
        let json = if self.accepted.is_some() || self.shows_within.is_some() {
            Some(
                serde_json::from_str::<serde_json::Value>(text)
                    .map_err(|error| format!("its answer is not JSON: {error}"))?,
            )
        } else {
            None
        };
        let strings = json.as_ref().map(strings_of).unwrap_or_default();
        let shown = match &self.shows_within {
            Some(within) => {
                let blocks: Vec<&String> = strings
                    .iter()
                    .filter(|string| string.starts_with(within.as_str()))
                    .collect();
                if blocks.is_empty() {
                    return Err(format!("it has no block that begins with {within:?}"));
                }
                blocks
                    .iter()
                    .map(|block| squeeze(block))
                    .collect::<String>()
            }
            None => squeeze(text),
        };
        for wanted in &self.shows {
            let wanted = squeeze(wanted);
            if !shown.contains(&wanted) {
                return Err(format!("it does not say {wanted:?}"));
            }
        }
        let one_spaced = |line: &str| line.split_whitespace().collect::<Vec<_>>().join(" ");
        let lines: Vec<String> = text.lines().map(one_spaced).collect();
        for wanted in &self.lines {
            let wanted = one_spaced(wanted);
            if !lines.contains(&wanted) {
                return Err(format!("it has no line {wanted:?}"));
            }
        }
        let lacks: Vec<String> = self
            .lacks
            .iter()
            .flat_map(|lack| {
                if lack == "{servers}" {
                    servers.to_vec()
                } else {
                    vec![lack.clone()]
                }
            })
            .map(|lack| lack.to_lowercase())
            .collect();
        let searched: Vec<String> = match &self.accepted {
            Some(block) => {
                let file = accepted.ok_or_else(|| {
                    format!(
                        "the file the accepted block carries, ~/{}, was not read",
                        block.file
                    )
                })?;
                let starting: Vec<&String> = strings
                    .iter()
                    .filter(|string| string.starts_with(block.starts.as_str()))
                    .collect();
                let [only] = starting.as_slice() else {
                    return Err(format!(
                        "{} blocks begin with {:?}, where exactly one may",
                        starting.len(),
                        block.starts
                    ));
                };
                if file.trim().is_empty() || !only.contains(file.trim()) {
                    return Err(format!(
                        "the block that begins with {:?} does not carry ~/{} whole",
                        block.starts, block.file
                    ));
                }
                strings
                    .iter()
                    .map(|string| {
                        if std::ptr::eq(string, *only) {
                            string.replacen(file.trim(), "", 1).to_lowercase()
                        } else {
                            string.to_lowercase()
                        }
                    })
                    .collect()
            }
            None => vec![text.to_lowercase()],
        };
        for lack in &lacks {
            if searched.iter().any(|string| string.contains(lack.as_str())) {
                return Err(format!("it holds {lack:?}"));
            }
        }
        Ok(())
    }
}

/// Every string a JSON value holds, at any depth, the names of its members aside, in order.
fn strings_of(value: &serde_json::Value) -> Vec<String> {
    let mut strings = Vec::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::String(string) => strings.push(string.clone()),
            serde_json::Value::Array(items) => pending.extend(items.iter().rev()),
            serde_json::Value::Object(members) => pending.extend(members.values().rev()),
            _ => {}
        }
    }
    strings
}

/// Where the person's own configuration names the servers the agent would start, each of which
/// the part switches off by name: the file, relative to the person's home, the table whose
/// sections name them, and the words that switch one off, with `{name}` for its name.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSwitches {
    /// The configuration file.
    pub file: String,
    /// The table whose sections each name a server.
    pub table: String,
    /// The words that switch one server off.
    pub switch: Vec<String>,
}

impl ServerSwitches {
    /// The servers a configuration file's `text` names: each section header `[<table>.<name>...]`,
    /// the name quoted or bare, once each, in the order they first appear.
    #[must_use]
    pub fn names_in(&self, text: &str) -> Vec<String> {
        let prefix = format!("[{}.", self.table);
        let mut names = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix(&prefix) else {
                continue;
            };
            let name: String = if let Some(quoted) = rest.strip_prefix('"') {
                quoted
                    .chars()
                    .take_while(|character| *character != '"')
                    .collect()
            } else {
                rest.chars()
                    .take_while(|character| {
                        character.is_ascii_alphanumeric() || "_-".contains(*character)
                    })
                    .collect()
            };
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
        names
    }
}

/// Each of `entries`, and where one has `{date}`, one for each of `dates` in its place.
#[must_use]
pub fn with_dates(entries: &[String], dates: &[String]) -> Vec<String> {
    entries
        .iter()
        .flat_map(|entry| {
            if entry.contains("{date}") {
                dates
                    .iter()
                    .map(|date| entry.replace("{date}", date))
                    .collect()
            } else {
                vec![entry.clone()]
            }
        })
        .collect()
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
    pub status: Option<Probe>,
    /// The commands that say, without calling a model, that the agent loads nothing of the
    /// person's own: no server, hook, plugin or skill.
    #[serde(default)]
    pub isolated: Vec<Probe>,
    /// Switches the agent's configuration is given in these parts, after its arguments, and on
    /// every probe: `{work}` is the working directory.
    #[serde(default)]
    pub switches: Vec<String>,
    /// Where the person's configuration names servers, each of which is switched off by name.
    #[serde(default)]
    pub server_switches: Option<ServerSwitches>,
    /// Files of the person's home the agent's own use may change, such as a login it refreshes:
    /// whether each changed is recorded, and nothing stops on it.
    #[serde(default)]
    pub recorded: Vec<String>,
    /// Files of the person's home the agent appends lines to, from which the lines holding the
    /// part's mark are removed after it, and listed.
    #[serde(default)]
    pub line_files: Vec<String>,
    /// The key that queues a prompt behind a running turn, where it is not the submit key.
    #[serde(default)]
    pub queue_key: Option<String>,
    /// Files that would load the person's own settings, hooks or servers into the agent, none of
    /// which may exist before it starts: `{config}` names the configuration directory of the run's
    /// own and `{work}` the working directory.
    #[serde(default)]
    pub absent: Vec<String>,
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
    /// each part that runs there. `{date}` is a local date as [`Account::conversations`] says. One
    /// that ends in `/*` is listed for the files directly in it, not for what its directories
    /// hold, which the list names on their own where a part writes there.
    #[serde(default)]
    pub directories: Vec<String>,
    /// Those of [`Account::directories`] whose files belong to one conversation or run each, such
    /// as the agent's conversation files: a file the part created there that holds its mark or the
    /// run's directory is the part's own and is removed. A file anywhere else, a database the
    /// person's own sessions share among them, is reported and never touched.
    #[serde(default)]
    pub removable: Vec<String>,
    /// Whether the agent stops at the first part after which a file it had in those directories
    /// was rewritten rather than appended to.
    #[serde(default)]
    pub stop_on_rewrite: bool,
    /// Where the agent keeps its conversations, relative to its configuration directory where it
    /// has one, and to the home it runs with otherwise. `{date}` is a local date as `YYYY/MM/DD`:
    /// the day the part starts, and the next, since a session started after midnight files under
    /// the day it starts.
    pub conversations: String,
    /// What marks the line of a conversation file that holds a prompt the person sent.
    pub prompt_line: String,
    /// Text the agent's first screen shows with the login.
    pub ready: String,
    /// Inputs typed first, each waited on by its screen text, to reach the composer.
    #[serde(default)]
    pub prepare: Vec<Keys>,
    /// Text the screen shows while the composer waits for a prompt; an agent that shows it while
    /// a turn runs too is taken to wait only once [`Account::busy`] is gone.
    pub composer: String,
    /// What submits a prompt typed in the composer.
    pub submit: String,
    /// What empties the composer without submitting it.
    pub clear: String,
    /// What marks the line of a conversation file that holds one of the agent's replies.
    pub reply_line: String,
    /// Text the agent's screen shows at the start of each of its replies, and nowhere else, where
    /// it has such a mark. Where it has none, a part that must see a reply begin asks for one
    /// that begins with the part's code in upper case, which only the model writes.
    #[serde(default)]
    pub reply_mark: Option<String>,
    /// What marks the line of a conversation file that records the answer to a tool approval:
    /// the command's result, or its refusal.
    pub decision_line: String,
    /// What marks the line of a conversation file that records a tool call that asks for approval,
    /// where only some calls do: each of these texts marks one. Then only the lines
    /// [`Account::decision_line`] marks that answer such a call, tied to it by the call's
    /// identifier (its `call_id`), count as answers; where the list is empty, every one does.
    #[serde(default)]
    pub decision_calls: Vec<String>,
    /// What marks the line of a conversation file that records a prompt queued behind a running
    /// turn, where the agent writes one.
    #[serde(default)]
    pub queued_line: Option<String>,
    /// What marks the line of a conversation file that starts a turn, where the agent writes one:
    /// a prompt that waited for a turn starts one of its own, and a prompt that steered one joins
    /// it without another starting.
    #[serde(default)]
    pub turn_line: Option<String>,
    /// Text the screen shows while a turn runs. The composer waits for a prompt while the screen
    /// shows [`Account::composer`] and not this.
    pub busy: String,
    /// A slash command that calls no model and changes no conversation, and the text it shows.
    pub slash: Keys,
    /// What closes the slash command's screen; nothing, where it leaves none to close.
    #[serde(default)]
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
    /// Whether those arguments start a new conversation from the saved one rather than continue
    /// it, because the agent lets no second process write a conversation another writes: then two
    /// processes on one conversation's identifier are not what the part shows, and it says so.
    #[serde(default)]
    pub resume_forks: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| (*text).to_owned()).collect()
    }

    fn probe(shows: &[&str], lines: &[&str], lacks: &[&str]) -> Probe {
        Probe {
            arguments: Vec::new(),
            shows: owned(shows),
            lines: owned(lines),
            lacks: owned(lacks),
            accepted: None,
            shows_within: None,
        }
    }

    #[test]
    fn a_probe_needs_each_text_and_whole_line_and_none_of_what_it_must_lack() {
        let servers = owned(&["pushary", "dtt"]);
        let answer =
            "hooks        stable   false\nplugins   stable  false\nLogged in using ChatGPT\n";
        assert_eq!(
            probe(
                &["Logged in using ChatGPT"],
                &["hooks stable false"],
                &["{servers}"]
            )
            .check(answer, &servers, None),
            Ok(())
        );
        assert_eq!(
            probe(&[], &["hooks stable false"], &[]).check("my_hooks stable false\n", &[], None),
            Err("it has no line \"hooks stable false\"".to_owned()),
            "a line is whole, not a line's end"
        );
        assert_eq!(
            probe(&["loggedIn\":true"], &[], &[]).check("{\"loggedIn\": true}", &[], None),
            Ok(()),
            "a text is found with spaces aside"
        );
        assert_eq!(
            probe(&[], &[], &["{servers}"]).check("uses DTT here", &servers, None),
            Err("it holds \"dtt\"".to_owned()),
            "what it must lack is compared without regard to case"
        );
    }

    /// A probe of a JSON answer that accepts the block carrying the person's `AGENTS.md`, and looks
    /// for its texts in the permissions block.
    fn prompt_probe() -> Probe {
        Probe {
            accepted: Some(Accepted {
                starts: "# AGENTS.md instructions".to_owned(),
                file: ".codex/AGENTS.md".to_owned(),
            }),
            shows_within: Some("<permissions".to_owned()),
            ..probe(&["Network access is restricted"], &[], &["{servers}"])
        }
    }

    #[test]
    fn a_json_answer_is_searched_but_for_the_one_block_that_carries_the_accepted_file() {
        let servers = owned(&["pushary"]);
        let file = "Ask me through pushary.";
        let answer = |blocks: &[&str]| {
            serde_json::json!([{ "content": blocks.iter().map(|text| serde_json::json!({ "text": text })).collect::<Vec<_>>() }])
                .to_string()
        };
        let permissions = "<permissions instructions> Network access is restricted.";
        let good = answer(&[
            permissions,
            "# AGENTS.md instructions for /\n\n<INSTRUCTIONS>\nAsk me through pushary.\n</INSTRUCTIONS>",
        ]);
        assert_eq!(prompt_probe().check(&good, &servers, Some(file)), Ok(()));
        let two = answer(&[
            permissions,
            "# AGENTS.md instructions Ask me through pushary.",
            "# AGENTS.md instructions another",
        ]);
        assert_eq!(
            prompt_probe().check(&two, &servers, Some(file)),
            Err(
                "2 blocks begin with \"# AGENTS.md instructions\", where exactly one may"
                    .to_owned()
            )
        );
        let more = answer(&[
            permissions,
            "# AGENTS.md instructions Ask me through pushary. And a pushary tool.",
        ]);
        assert_eq!(
            prompt_probe().check(&more, &servers, Some(file)),
            Err("it holds \"pushary\"".to_owned()),
            "what the block holds besides the file is searched"
        );
        let other = answer(&[permissions, "# AGENTS.md instructions something else"]);
        assert!(
            prompt_probe()
                .check(&other, &servers, Some(file))
                .is_err_and(|why| why.contains("does not carry ~/.codex/AGENTS.md whole"))
        );
        let elsewhere = answer(&[
            "<permissions instructions> Network access is enabled.",
            "# AGENTS.md instructions Ask me through pushary. Network access is restricted",
        ]);
        assert_eq!(
            prompt_probe().check(&elsewhere, &servers, Some(file)),
            Err("it does not say \"Networkaccessisrestricted\"".to_owned()),
            "a text is looked for in the block that states it, not in the person's file"
        );
        assert!(
            prompt_probe()
                .check("not json", &servers, Some(file))
                .is_err_and(|why| why.starts_with("its answer is not JSON")),
        );
    }

    #[test]
    fn an_approval_is_the_parts_command_alone_on_its_own_line() {
        let codex = Approval {
            shows: "Would you like to run the following command?".to_owned(),
            allow: "y".to_owned(),
            deny: "d".to_owned(),
            command_line: Some("$ ".to_owned()),
            others: Vec::new(),
            refuse: Some("\u{1b}".to_owned()),
        };
        let rows = |lines: &[&str]| owned(lines);
        let command = "echo kr0123 >> approved.log";
        assert_eq!(
            codex.names_only(
                &rows(&[
                    "  Would you like to run the following command?",
                    "",
                    "  $ echo kr0123 >> approved.log",
                    "",
                    "› 1. Yes, proceed (y)"
                ]),
                command
            ),
            Ok(())
        );
        assert!(
            codex
                .names_only(
                    &rows(&["  $ echo kr0123 >> approved.log", "  curl example.com", ""]),
                    command
                )
                .is_err(),
            "a command that goes on to another line is not the part's"
        );
        assert!(
            codex
                .names_only(
                    &rows(&["  $ echo kr0123 >> approved.log && rm x", ""]),
                    command
                )
                .is_err(),
            "a longer command is not the part's"
        );
        assert!(
            codex
                .names_only(
                    &rows(&["  $ echo kr0123 >> approved.log", "", "  $ ls", ""]),
                    command
                )
                .is_err(),
            "a dialog that shows another command is not the part's"
        );
        assert_eq!(codex.refusal(), "\u{1b}");
        let claude = Approval {
            command_line: None,
            refuse: None,
            ..codex
        };
        assert_eq!(
            claude.names_only(
                &rows(&[
                    " Bash command",
                    "   echo kr0123 >> approved.log",
                    "   Append the marker",
                    " Do you want to proceed?"
                ]),
                command
            ),
            Ok(())
        );
        assert_eq!(claude.refusal(), "d");
    }

    #[test]
    fn servers_are_named_by_their_section_headers_once_each() {
        let switches = ServerSwitches {
            file: ".codex/config.toml".to_owned(),
            table: "mcp_servers".to_owned(),
            switch: Vec::new(),
        };
        let text = "[mcp_servers.peekaboo]\ncommand = \"x\"\n[mcp_servers.\"with.dot\"]\n[mcp_servers.slack]\n[mcp_servers.slack.env]\n[projects.\"/p\"]\n";
        assert_eq!(
            switches.names_in(text),
            vec![
                "peekaboo".to_owned(),
                "with.dot".to_owned(),
                "slack".to_owned()
            ]
        );
    }

    #[test]
    fn a_date_in_a_path_stands_for_each_date() {
        let dates = owned(&["2026/09/27", "2026/09/28"]);
        assert_eq!(
            with_dates(&owned(&[".codex/sessions/{date}", ".codex/*"]), &dates),
            owned(&[
                ".codex/sessions/2026/09/27",
                ".codex/sessions/2026/09/28",
                ".codex/*"
            ])
        );
    }
}
