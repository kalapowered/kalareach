//! What an agent that keeps its data in a directory the person's own sessions share needs before it
//! runs with their login: a sandbox its processes cannot leave, a record that trusts the run's
//! folder, a project file that switches the person's servers off, and checks that the files it
//! shares with them are as they were.
//!
//! Everything here is a plain function of text and paths, so that what a part relies on is tested
//! without an agent. The layout is Kimi Code's: `workspace-trust/wd_<name>_<hash>` records,
//! `workspaces.json`, `sessions/wd_<name>_<hash>/session_<uuid>/agents/main/wire.jsonl`, a
//! credentials file for each login slot named by the configuration's OAuth key, and a project file
//! `<folder>/.kimi-code/mcp.json`.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The directory of the person's data that holds the trust records.
pub const TRUST: &str = "workspace-trust";

/// The longest name a folder's key carries of the folder's own.
const SLUG_LENGTH: usize = 40;

/// The key the agent files a folder under, as the pinned build computes it: `wd_`, the folder's last
/// component in lower case with each run of other characters than letters, digits, `.`, `_` and `-`
/// turned into `-`, trimmed of `-` and cut to 40 characters, then `_` and the first twelve
/// hexadecimal digits of the SHA-256 of the path without a trailing `/`.
#[must_use]
pub fn workdir_key(folder: &Path) -> String {
    let text = folder.display().to_string().replace('\\', "/");
    let normalized = text.trim_end_matches('/');
    let name = normalized.rsplit('/').next().unwrap_or(normalized);
    let mut slug = String::new();
    let mut in_run = false;
    for character in name.to_lowercase().chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() || "._-".contains(character)
        {
            slug.push(character);
            in_run = false;
        } else if !in_run {
            slug.push('-');
            in_run = true;
        }
    }
    let trimmed: String = slug.trim_matches('-').chars().take(SLUG_LENGTH).collect();
    let trimmed = trimmed.trim_matches('-');
    let slug = if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "workspace"
    } else {
        trimmed
    };
    let digest = kr_cbor::sha256(normalized.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("wd_{slug}_{}", &hex[..12])
}

/// The record that trusts `folder`, as the agent writes it: compact JSON with the folder and the
/// time in milliseconds.
#[must_use]
pub fn trust_body(folder: &Path, now_ms: u64) -> String {
    serde_json::json!({ "root": folder.display().to_string(), "trustedAt": now_ms }).to_string()
}

/// Writes the record that trusts `folder` in `directory`, the person's `workspace-trust`, with mode
/// 0600, and returns its path. A record already there for this key is not overwritten.
///
/// # Errors
///
/// Returns why the record was not written, and that one exists.
pub fn write_trust(directory: &Path, folder: &Path, now_ms: u64) -> Result<PathBuf, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = directory.join(workdir_key(folder));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("the trust record cannot be created: {error}"))?;
    file.write_all(trust_body(folder, now_ms).as_bytes())
        .map_err(|error| format!("the trust record cannot be written: {error}"))?;
    Ok(path)
}

/// Removes every record in `directory` whose `root` is `folder`, whatever key it is filed under,
/// and returns how many it removed. The records are read to tell; a file that is no record is left.
///
/// # Errors
///
/// Returns why the directory could not be read or a record could not be removed.
pub fn remove_trust(directory: &Path, folder: &Path) -> Result<usize, String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("the trust records cannot be listed: {error}"))?;
    let wanted = folder.display().to_string();
    let mut removed = 0;
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if record.get("root").and_then(Value::as_str) == Some(wanted.as_str()) {
            std::fs::remove_file(entry.path())
                .map_err(|error| format!("a trust record cannot be removed: {error}"))?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// How many records in `directory` name `folder` as their root.
#[must_use]
pub fn trust_records_for(directory: &Path, folder: &Path) -> usize {
    let wanted = folder.display().to_string();
    std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(|record| record.get("root").and_then(Value::as_str) == Some(wanted.as_str()))
        .count()
}

/// The names of the servers a JSON configuration lists under `member`, in the order the file
/// gives them.
///
/// # Errors
///
/// Returns why the text is not a configuration with that member.
pub fn server_names(text: &str, member: &str) -> Result<Vec<String>, String> {
    let document: Value = serde_json::from_str(text)
        .map_err(|error| format!("the servers' configuration is not JSON: {error}"))?;
    let servers = document
        .get(member)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("the servers' configuration has no `{member}` object"))?;
    Ok(servers.keys().cloned().collect())
}

/// The project file that switches each of `names` off: each server with `entry`.
#[must_use]
pub fn project_servers(names: &[String], member: &str, entry: &Value) -> String {
    let servers: serde_json::Map<String, Value> = names
        .iter()
        .map(|name| (name.clone(), entry.clone()))
        .collect();
    let mut document = serde_json::Map::new();
    document.insert(member.to_owned(), Value::Object(servers));
    let mut text = serde_json::to_string_pretty(&Value::Object(document)).unwrap_or_default();
    text.push('\n');
    text
}

/// Whether `text` is the project file written for `names`, and nothing else.
#[must_use]
pub fn is_project_servers(text: &str, names: &[String], member: &str, entry: &Value) -> bool {
    text == project_servers(names, member, entry)
}

/// Whether some directory above `folder` holds a `.git`, which would make the agent read
/// instruction files from the directories between them.
#[must_use]
pub fn git_above(folder: &Path) -> Option<PathBuf> {
    folder
        .ancestors()
        .find(|directory| directory.join(".git").exists())
        .map(Path::to_path_buf)
}

/// Whether `after` is `before` with, at most, workspaces added that name `folder` as their root: the
/// document's other members and every earlier workspace are as they were.
///
/// # Errors
///
/// Returns what differs, in words that name no workspace of the person's.
pub fn workspaces_verdict(before: &str, after: &str, folder: &Path) -> Result<(), String> {
    let parse = |text: &str, what: &str| -> Result<Value, String> {
        serde_json::from_str(text).map_err(|error| format!("{what} is not JSON: {error}"))
    };
    let (before, after) = (
        parse(before, "the earlier list")?,
        parse(after, "the list now")?,
    );
    let (Some(before), Some(after)) = (before.as_object(), after.as_object()) else {
        return Err("the workspace list is not an object".to_owned());
    };
    let empty = serde_json::Map::new();
    for (key, value) in before {
        if key == "workspaces" {
            continue;
        }
        if after.get(key) != Some(value) {
            return Err(format!("the list's member `{key}` is not as it was"));
        }
    }
    if after.keys().any(|key| !before.contains_key(key)) {
        return Err("the list has a member it did not have".to_owned());
    }
    let earlier = before
        .get("workspaces")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let now = after
        .get("workspaces")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let wanted = folder.display().to_string();
    for (key, entry) in earlier {
        if now.get(key) != Some(entry) {
            return Err("an earlier workspace changed or went".to_owned());
        }
    }
    for (key, entry) in now {
        if !earlier.contains_key(key)
            && entry.get("root").and_then(Value::as_str) != Some(wanted.as_str())
        {
            return Err("a workspace was added that is not the run's folder".to_owned());
        }
    }
    Ok(())
}

/// The tools through which the agent starts a subagent. Its requests to the model are not turns
/// the part's ledger counts, so the part stops at the first sign of one.
const SUBAGENT_TOOLS: [&str; 2] = ["Agent", "AgentSwarm"];

/// Whether one line of a conversation's wire file starts a subagent: a call of one of
/// [`SUBAGENT_TOOLS`], or a record of a subagent's own, at the line's top level or in its event.
fn line_starts_a_subagent(line: &str) -> bool {
    if !line.contains("tool.call") && !line.contains("subagent.") {
        return false;
    }
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    let kind = |holder: &Value| {
        holder
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let event = value.get("event").unwrap_or(&Value::Null);
    [kind(&value), kind(event)]
        .into_iter()
        .flatten()
        .any(|kind| kind.starts_with("subagent."))
        || (kind(event).as_deref() == Some("tool.call")
            && event
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| SUBAGENT_TOOLS.contains(&name)))
}

/// Whether a subagent has started in any conversation of `bucket`, the run's directory of
/// sessions: a directory under a session's `agents` other than the main agent's, or a line of the
/// main agent's wire file that calls one of [`SUBAGENT_TOOLS`] or records a subagent. A bucket that
/// is not there yet holds none. It names what it saw by kind, never a path or a line.
#[must_use]
pub fn subagent_started(bucket: &Path) -> Option<String> {
    let sessions = match std::fs::read_dir(bucket) {
        Ok(sessions) => sessions,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            return Some(format!("the run's sessions cannot be listed: {error}"));
        }
    };
    for session in sessions.flatten() {
        let agents = session.path().join("agents");
        let entries = match std::fs::read_dir(&agents) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Some(format!("a conversation's agents cannot be listed: {error}"));
            }
        };
        if entries.flatten().any(|entry| entry.file_name() != "main") {
            return Some(
                "an agent other than the main one has a directory in a conversation".to_owned(),
            );
        }
        match std::fs::read(agents.join("main").join("wire.jsonl")) {
            Ok(bytes) => {
                if String::from_utf8_lossy(&bytes)
                    .lines()
                    .any(line_starts_a_subagent)
                {
                    return Some(
                        "the main agent's conversation records a subagent start".to_owned(),
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Some(format!(
                    "a conversation's wire file cannot be read: {error}"
                ));
            }
        }
    }
    None
}

/// The strings of at least sixteen characters a JSON document holds, at any depth: what a login
/// file keeps of its tokens. They are searched for, never printed.
#[must_use]
pub fn secret_values(text: &str) -> Vec<String> {
    let Ok(document) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut pending = vec![&document];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(string) if string.chars().count() >= 16 => found.push(string.clone()),
            Value::Array(items) => pending.extend(items),
            Value::Object(members) => pending.extend(members.values()),
            _ => {}
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The strings the login in use keeps now, which differ from those read before a part where the
/// agent refreshed its token while it ran: both are searched for. Read again from `data` (the
/// person's data directory), never printed.
///
/// # Errors
///
/// Returns why the credentials file cannot be read or holds no string.
pub fn current_secrets(data: &Path, slot: &str) -> Result<Vec<String>, String> {
    let path = data.join("credentials").join(format!("{slot}.json"));
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("the login's file cannot be read again: {error}"))?;
    let values = secret_values(&text);
    if values.is_empty() {
        return Err("the login's file holds no token now".to_owned());
    }
    Ok(values)
}

/// The files of the two login slots as the configuration names them: the credentials file and the
/// lock of the OAuth key of the managed provider, by name only, or nothing where it names none.
#[must_use]
pub fn active_slot(config: &str, provider_table: &str) -> Option<String> {
    let header = format!("[{provider_table}.oauth]");
    let mut inside = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == header;
            continue;
        }
        if inside
            && let Some(value) = line
                .strip_prefix("key")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix('='))
        {
            return value
                .trim()
                .trim_matches('"')
                .rsplit('/')
                .next()
                .map(str::to_owned);
        }
    }
    None
}

/// What the person's configuration sets that changes what an unasked tool or a permission does,
/// counted by name only.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Settings {
    /// The permission rules the configuration has.
    pub rules: usize,
    /// Those that allow a tool that is not one of an MCP server's (`mcp__` patterns).
    pub allow_built_in: usize,
    /// Whether it turns on the mode that runs everything without asking, or names a permission
    /// mode other than manual.
    pub mode_not_manual: bool,
    /// Whether it lists extra skill directories, hooks or plugins.
    pub loads_more: bool,
}

impl Settings {
    /// Why the run may not go on, where it may not.
    #[must_use]
    pub const fn problem(&self) -> Option<&'static str> {
        if self.allow_built_in > 0 {
            Some("the configuration allows a built-in tool without asking")
        } else if self.mode_not_manual {
            Some("the configuration sets a permission mode other than manual")
        } else if self.loads_more {
            Some("the configuration loads skills, hooks or plugins of its own")
        } else {
            None
        }
    }
}

/// What the configuration `text` (TOML) sets that `Settings` counts. Only the text of the rules'
/// `pattern` and `decision` lines and the names of a few keys and tables are read.
#[must_use]
pub fn settings_of(text: &str) -> Settings {
    let mut settings = Settings::default();
    let mut table = String::new();
    let mut decision = String::new();
    let mut pattern = String::new();
    let mut rule_open = false;
    let finish = |settings: &mut Settings, decision: &str, pattern: &str, open: bool| {
        if open {
            settings.rules += 1;
            if decision == "allow" && !pattern.starts_with("mcp__") {
                settings.allow_built_in += 1;
            }
        }
    };
    let quoted = |value: &str| value.trim().trim_matches('"').to_owned();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            finish(&mut settings, &decision, &pattern, rule_open);
            decision.clear();
            pattern.clear();
            rule_open = line == "[[permission.rules]]";
            table = line.trim_matches(|c| c == '[' || c == ']').to_owned();
            if table.starts_with("hooks") || table.starts_with("plugins") {
                settings.loads_more = true;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match (table.as_str(), key) {
            ("permission.rules", "decision") if rule_open => decision = quoted(value),
            ("permission.rules", "pattern") if rule_open => pattern = quoted(value),
            ("", "yolo") | ("permission", "yolo") => {
                if value != "false" {
                    settings.mode_not_manual = true;
                }
            }
            ("permission", "mode") | ("", "permission_mode") => {
                if quoted(value) != "manual" {
                    settings.mode_not_manual = true;
                }
            }
            ("", "extra_skill_dirs" | "hooks" | "plugins") => settings.loads_more = true,
            _ => {}
        }
    }
    finish(&mut settings, &decision, &pattern, rule_open);
    settings
}

/// What the person's data directory says before a part starts, read once: the login slot in use,
/// what the configuration sets, the servers to switch off, and the login files' long strings.
#[derive(Clone, Debug)]
pub struct Setup {
    /// The credentials file of the login in use, by name.
    pub slot: String,
    /// What the configuration sets that changes what runs unasked.
    pub settings: Settings,
    /// The servers the person's configuration names.
    pub servers: Vec<String>,
    /// The strings a login file keeps, which nothing the part writes may hold.
    pub secrets: Vec<String>,
    /// The credentials files of every other slot, and the files of the OAuth directory, relative to
    /// the person's home: none may change.
    pub other_logins: Vec<String>,
}

impl Setup {
    /// Reads `data` (relative to `person`) as the entry describes it.
    ///
    /// # Errors
    ///
    /// Returns why a file that must be read cannot be, or why the configuration names no login.
    pub fn read(
        person: &Path,
        data: &str,
        provider: &str,
        servers: &crate::build::ProjectServers,
    ) -> Result<Self, String> {
        let directory = person.join(data);
        let read = |relative: &str| {
            std::fs::read_to_string(directory.join(relative))
                .map_err(|error| format!("{data}/{relative} cannot be read: {error}"))
        };
        let config = read("config.toml")?;
        let slot = active_slot(&config, provider).ok_or_else(|| {
            "the configuration names no login for the agent's provider".to_owned()
        })?;
        let credentials = format!("credentials/{slot}.json");
        let secrets = secret_values(&read(&credentials)?);
        if secrets.is_empty() {
            return Err("the login's file holds no token".to_owned());
        }
        let names = server_names(&read(&servers.source)?, &servers.member)?;
        let mut other_logins = Vec::new();
        for (subdirectory, keep) in [
            ("credentials", Some(format!("{slot}.json"))),
            ("oauth", None),
        ] {
            let entries = std::fs::read_dir(directory.join(subdirectory))
                .map_err(|error| format!("{data}/{subdirectory} cannot be listed: {error}"))?;
            for entry in entries {
                let entry = entry.map_err(|error| format!("{data}/{subdirectory}: {error}"))?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if keep.as_deref() != Some(name.as_str()) {
                    other_logins.push(format!("{data}/{subdirectory}/{name}"));
                }
            }
        }
        other_logins.sort();
        Ok(Self {
            slot,
            settings: settings_of(&config),
            servers: names,
            secrets,
            other_logins,
        })
    }
}

/// The paths the sandbox profile's parameters name, each as the system resolves it.
#[derive(Clone, Debug)]
pub struct Layout {
    /// The run's home, which the agent gets as its own.
    pub home: PathBuf,
    /// The run's working directory, the folder the agent works in.
    pub work: PathBuf,
    /// The run's temporary directory.
    pub tmp: PathBuf,
    /// The run's empty skills directory.
    pub skills: PathBuf,
    /// The run's links to the installed build and its runtimes.
    pub agent: PathBuf,
    /// The pinned build's directory.
    pub build: PathBuf,
    /// The managed shell's packages, whose shell the agent's own tools start.
    pub shells: PathBuf,
    /// The person's data directory the agent shares with their own sessions.
    pub data: PathBuf,
    /// The person's home, of which the profile denies the rest.
    pub person: PathBuf,
    /// The credentials file of the login in use, by name: the one file of the credentials
    /// directory the agent may write.
    pub slot: String,
    /// The loopback port of the run's proxy.
    pub proxy_port: u16,
}

impl Layout {
    /// The parameters the committed profile takes, as `-D name=value` words.
    #[must_use]
    pub fn parameters(&self) -> Vec<(&'static str, String)> {
        let text = |path: &Path| path.display().to_string();
        vec![
            ("HOME", text(&self.home)),
            ("WORK", text(&self.work)),
            ("TMP", text(&self.tmp)),
            ("SKILLS", text(&self.skills)),
            ("AGENT", text(&self.agent)),
            ("BUILD", text(&self.build)),
            ("SHELLS", text(&self.shells)),
            ("DATA", text(&self.data)),
            ("PERSON", text(&self.person)),
            ("SLOT", format!("{}.json", self.slot)),
            ("PROXY_PORT", self.proxy_port.to_string()),
        ]
    }
}

/// The words that start `command` with `arguments` inside the sandbox profile at `profile`: the
/// system's own `sandbox-exec`, by its full path, applies it and then executes the program in the
/// same process, so the agent stays the shell's own child.
#[must_use]
pub fn sandbox_words(
    profile: &Path,
    layout: &Layout,
    command: &str,
    arguments: &[String],
) -> Vec<String> {
    let mut words = vec!["/usr/bin/sandbox-exec".to_owned()];
    for (name, value) in layout.parameters() {
        words.push("-D".to_owned());
        words.push(format!("{name}={value}"));
    }
    words.push("-f".to_owned());
    words.push(profile.display().to_string());
    words.push(command.to_owned());
    words.extend(arguments.iter().cloned());
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_is_filed_under_the_key_the_agent_computes() {
        // The pinned build files a trusted folder under this key (a scratch run's record for a
        // folder named the same way had the key its path gives here).
        assert_eq!(
            workdir_key(Path::new("/private/tmp/kr-scratch/agent-run/work")),
            "wd_work_65647cb38e3f"
        );
        assert_eq!(
            workdir_key(Path::new("/x/My Project (2)/"))
                .split('_')
                .nth(1),
            Some("my-project-2"),
            "a run of other characters is one dash, and a trailing slash is not part of the path"
        );
        assert!(workdir_key(Path::new("/x/---")).starts_with("wd_workspace_"));
        let long = format!("/x/{}", "a".repeat(80));
        assert_eq!(
            workdir_key(Path::new(&long)).len(),
            "wd_".len() + 40 + 1 + 12
        );
    }

    #[test]
    fn a_trust_record_is_written_once_and_every_record_for_the_folder_is_removed() {
        let directory = std::env::temp_dir().join(format!("kr-confine-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let folder = Path::new("/private/tmp/kr-run/w");
        let path = write_trust(&directory, folder, 1_790_000_000_000).expect("written");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            r#"{"root":"/private/tmp/kr-run/w","trustedAt":1790000000000}"#
        );
        assert!(
            write_trust(&directory, folder, 1).is_err(),
            "never overwritten"
        );
        // Another record for the same root under another key, and one for another folder.
        std::fs::write(directory.join("wd_old_000000000000"), trust_body(folder, 5))
            .expect("write");
        std::fs::write(
            directory.join("wd_other_111111111111"),
            trust_body(Path::new("/other"), 5),
        )
        .expect("write");
        assert_eq!(trust_records_for(&directory, folder), 2);
        assert_eq!(remove_trust(&directory, folder), Ok(2));
        assert_eq!(trust_records_for(&directory, folder), 0);
        assert!(directory.join("wd_other_111111111111").exists());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_project_file_names_each_server_off_and_only_that() {
        let names = server_names(
            r#"{"mcpServers":{"alpha":{"command":"a"},"beta":{"url":"http://x"}},"other":1}"#,
            "mcpServers",
        )
        .expect("names");
        assert_eq!(names, ["alpha", "beta"]);
        assert!(server_names("{}", "mcpServers").is_err());
        let entry = serde_json::json!({"command": "/usr/bin/false", "enabled": false});
        let text = project_servers(&names, "mcpServers", &entry);
        assert!(is_project_servers(&text, &names, "mcpServers", &entry));
        assert!(!is_project_servers(
            &text.replace("beta", "gamma"),
            &names,
            "mcpServers",
            &entry
        ));
        assert!(text.contains(r#""enabled": false"#));
    }

    #[test]
    fn only_the_runs_own_folder_may_be_added_to_the_workspace_list() {
        let folder = Path::new("/private/tmp/kr-run/w");
        let before = r#"{"version":1,"workspaces":{"a":{"root":"/x","last_opened_at":1}},"deleted_workspace_ids":[]}"#;
        let added = r#"{"version":1,"workspaces":{"a":{"root":"/x","last_opened_at":1},"b":{"root":"/private/tmp/kr-run/w"}},"deleted_workspace_ids":[]}"#;
        assert_eq!(workspaces_verdict(before, before, folder), Ok(()));
        assert_eq!(workspaces_verdict(before, added, folder), Ok(()));
        let other = added.replace("/private/tmp/kr-run/w", "/elsewhere");
        assert!(workspaces_verdict(before, &other, folder).is_err());
        let touched = before.replace("\"last_opened_at\":1", "\"last_opened_at\":2");
        assert!(workspaces_verdict(before, &touched, folder).is_err());
        let dropped = r#"{"version":1,"workspaces":{},"deleted_workspace_ids":[]}"#;
        assert!(workspaces_verdict(before, dropped, folder).is_err());
        let versioned = before.replace("\"version\":1", "\"version\":2");
        assert!(workspaces_verdict(before, &versioned, folder).is_err());
        let extra = before.replace(
            "\"deleted_workspace_ids\":[]",
            "\"deleted_workspace_ids\":[],\"more\":1",
        );
        assert!(workspaces_verdict(before, &extra, folder).is_err());
    }

    #[test]
    fn a_login_files_long_strings_are_what_is_searched_for() {
        let values = secret_values(
            r#"{"access_token":"abcdefghijklmnopqrstuvwxyz","nested":{"refresh":["0123456789abcdef0123"]},"short":"x","n":5}"#,
        );
        assert_eq!(
            values,
            ["0123456789abcdef0123", "abcdefghijklmnopqrstuvwxyz"]
        );
        assert!(secret_values("not json").is_empty());
    }

    #[test]
    fn the_active_slot_is_the_name_the_managed_providers_key_gives() {
        let config = "default_model = \"x\"\n[providers.\"managed:kimi-code\"]\ntype = \"kimi\"\n\n[providers.\"managed:kimi-code\".oauth]\nstorage = \"file\"\nkey = \"oauth/kimi-code-env-0123456789abcdef\"\noauth_host = \"https://auth.example\"\n";
        assert_eq!(
            active_slot(config, "providers.\"managed:kimi-code\""),
            Some("kimi-code-env-0123456789abcdef".to_owned())
        );
        assert_eq!(active_slot(config, "providers.other"), None);
    }

    #[test]
    fn the_settings_that_would_let_a_tool_run_unasked_are_counted_by_name() {
        let quiet = "default_model = \"x\"\n[[permission.rules]]\ndecision = \"allow\"\nscope = \"user\"\npattern = \"mcp__a__b\"\n\n[[permission.rules]]\ndecision = \"deny\"\npattern = \"Bash\"\n\n[thinking]\nenabled = true\n";
        let settings = settings_of(quiet);
        assert_eq!(
            settings,
            Settings {
                rules: 2,
                allow_built_in: 0,
                mode_not_manual: false,
                loads_more: false
            }
        );
        assert_eq!(settings.problem(), None);
        let allows = quiet.replace("mcp__a__b", "Read");
        assert_eq!(
            settings_of(&allows).problem(),
            Some("the configuration allows a built-in tool without asking")
        );
        assert!(settings_of("yolo = true\n").mode_not_manual);
        assert!(!settings_of("yolo = false\n").mode_not_manual);
        assert!(settings_of("[permission]\nmode = \"auto\"\n").mode_not_manual);
        assert!(!settings_of("[permission]\nmode = \"manual\"\n").mode_not_manual);
        assert!(settings_of("[[hooks]]\nevent = \"x\"\n").loads_more);
        assert!(settings_of("extra_skill_dirs = [\"a\"]\n").loads_more);
    }

    #[test]
    fn the_agent_is_started_by_the_systems_sandbox_program_with_the_profile_parameters() {
        let layout = Layout {
            home: "/r/h".into(),
            work: "/r/w".into(),
            tmp: "/r/tmp".into(),
            skills: "/r/skills".into(),
            agent: "/r/agent".into(),
            build: "/t/kimi".into(),
            shells: "/s".into(),
            data: "/p/.kimi-code".into(),
            person: "/p".into(),
            slot: "kimi-code-env-0123".into(),
            proxy_port: 4242,
        };
        let words = sandbox_words(
            Path::new("/plugins/kimi-code.sb"),
            &layout,
            "kimi",
            &["-m".to_owned(), "alias".to_owned()],
        );
        assert_eq!(words[0], "/usr/bin/sandbox-exec");
        assert!(
            words
                .windows(2)
                .any(|pair| pair == ["-D", "PROXY_PORT=4242"])
        );
        assert!(
            words
                .windows(2)
                .any(|pair| pair == ["-D", "DATA=/p/.kimi-code"])
        );
        let tail: Vec<&str> = words[words.len() - 5..]
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(tail, ["-f", "/plugins/kimi-code.sb", "kimi", "-m", "alias"]);
    }

    #[test]
    fn a_git_directory_above_a_folder_is_found() {
        let root = std::env::temp_dir().join(format!("kr-confine-git-{}", kr_ipc::new_uuid()));
        let folder = root.join("a/b");
        std::fs::create_dir_all(&folder).expect("directories");
        assert_eq!(
            git_above(&folder).filter(|found| found.starts_with(&root)),
            None
        );
        std::fs::create_dir_all(root.join(".git")).expect("a .git");
        assert_eq!(git_above(&folder), Some(root.clone()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_subagent_start_is_seen_by_a_directory_or_by_a_line_of_the_main_wire_file() {
        let bucket = std::env::temp_dir().join(format!("kr-confine-sub-{}", kr_ipc::new_uuid()));
        assert_eq!(subagent_started(&bucket), None, "no bucket holds none");
        let agents = bucket.join("session_a").join("agents");
        std::fs::create_dir_all(agents.join("main")).expect("directories");
        let wire = agents.join("main").join("wire.jsonl");
        // The prompt that tells the model about the tool, a snapshot that lists it, and a call of
        // a tool that is not one of the two are not a start.
        let quiet = concat!(
            r#"{"type":"profile.bind","systemPrompt":"use Agent(subagent_type=\"explore\") to look"}"#,
            "\n",
            r#"{"type":"llm.tools_snapshot","tools":[{"name":"Agent"},{"name":"AgentSwarm"}]}"#,
            "\n",
            r#"{"type":"context.append_loop_event","event":{"type":"tool.call","name":"Read","args":{}}}"#,
            "\n",
            "a line cut off mid-wri",
        );
        std::fs::write(&wire, quiet).expect("write");
        assert_eq!(subagent_started(&bucket), None);
        for call in ["Agent", "AgentSwarm"] {
            let line = format!(
                "{quiet}\n{{\"type\":\"context.append_loop_event\",\"event\":{{\"type\":\"tool.call\",\"name\":\"{call}\",\"args\":{{}}}}}}\n"
            );
            std::fs::write(&wire, line).expect("write");
            assert!(subagent_started(&bucket).is_some(), "a call of {call}");
        }
        std::fs::write(
            &wire,
            format!("{quiet}\n{{\"type\":\"subagent.spawned\",\"subagentId\":\"x\"}}\n"),
        )
        .expect("write");
        assert!(
            subagent_started(&bucket).is_some(),
            "a record of a subagent"
        );
        std::fs::write(&wire, quiet).expect("write");
        assert_eq!(subagent_started(&bucket), None);
        std::fs::create_dir_all(agents.join("sub_1")).expect("a subagent's directory");
        assert!(
            subagent_started(&bucket).is_some(),
            "a directory of another agent"
        );
        let _ = std::fs::remove_dir_all(&bucket);
    }

    #[test]
    fn the_login_in_use_is_read_again_for_the_strings_a_refresh_changed() {
        let data = std::env::temp_dir().join(format!("kr-confine-login-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(data.join("credentials")).expect("directories");
        assert!(
            current_secrets(&data, "slot-a").is_err(),
            "a file that is not there"
        );
        std::fs::write(
            data.join("credentials/slot-a.json"),
            r#"{"access":"abcdefghijklmnopqrstuvwxyz"}"#,
        )
        .expect("write");
        assert_eq!(
            current_secrets(&data, "slot-a"),
            Ok(vec!["abcdefghijklmnopqrstuvwxyz".to_owned()])
        );
        std::fs::write(data.join("credentials/slot-a.json"), r#"{"n":1}"#).expect("write");
        assert!(
            current_secrets(&data, "slot-a").is_err(),
            "no string at all"
        );
        let _ = std::fs::remove_dir_all(&data);
    }
}
