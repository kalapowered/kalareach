//! The closed shape of each registration file a native bridge installs.
//!
//! An application reads far more from a plugin's files than a host can list: a server can carry a
//! helper that a shell runs, a hook can call a tool or post to an address, a manifest can name a
//! dependency that is enabled with it. A check that looked for what is wrong would be a list that
//! grows with every release of the application, so what is checked is what is right: each file a
//! bridge installs has exactly the members this host names for it, with the kinds of value it names,
//! and nothing else. A member that is not on the list is refused, whatever it holds.

use serde_json::{Map, Value};

type Checked = std::result::Result<(), String>;

/// Checks that `value`, the registration file at `tail` of the directory `directory` an
/// application `application` reads, has the shape this host names for it.
///
/// # Errors
///
/// Returns why the file is not one a bridge may install.
pub(super) fn check(application: &str, directory: &str, tail: &str, value: &Value) -> Checked {
    match (application, tail) {
        ("Claude Code", ".claude-plugin/plugin.json") => manifest(
            value,
            &[
                "name",
                "displayName",
                "version",
                "description",
                "channels",
                "defaultEnabled",
            ],
            directory,
        ),
        ("Claude Code", ".mcp.json") => servers(application, value),
        ("Gemini CLI", "gemini-extension.json") => {
            manifest(value, &["name", "version", "description"], directory)
        }
        ("Gemini CLI", ".gemini-extension-install.json") => record(value, directory),
        (_, "hooks/hooks.json") => hooks(application, value),
        _ => Err("this host names no shape for it".to_owned()),
    }
}

/// The members of `value`, which has to be an object holding only members of `allowed`.
fn members<'a>(
    value: &'a Value,
    allowed: &[&str],
    what: &str,
) -> Result<&'a Map<String, Value>, String> {
    let Value::Object(members) = value else {
        return Err(format!("{what} is not an object"));
    };
    match members
        .keys()
        .find(|member| !allowed.contains(&member.as_str()))
    {
        Some(other) => Err(format!(
            "{what} holds {other}, which this host does not name for it"
        )),
        None => Ok(members),
    }
}

fn is_text(value: &Value) -> bool {
    value.is_string()
}

/// A plugin's or an extension's manifest: text members, the name the directory has, and for a
/// plugin its channels, each naming a server and nothing else, and whether it is on by default.
fn manifest(value: &Value, allowed: &[&str], directory: &str) -> Checked {
    let held = members(value, allowed, "the manifest")?;
    if held.get("name").and_then(Value::as_str) != Some(directory) {
        return Err(format!(
            "the manifest is not named {directory}, the directory it is installed in"
        ));
    }
    for (member, kind) in held {
        let fits = match member.as_str() {
            "channels" => kind.as_array().is_some_and(|channels| {
                channels.iter().all(|channel| {
                    members(channel, &["server"], "a channel")
                        .is_ok_and(|held| held.get("server").is_some_and(is_text))
                })
            }),
            "defaultEnabled" => kind.is_boolean(),
            _ => is_text(kind),
        };
        if !fits {
            return Err(format!(
                "the manifest's {member} is not a value this host names for it"
            ));
        }
    }
    Ok(())
}

/// An MCP server file: servers that start a program, each with its kind, its command and its
/// arguments, and no member that makes a server connect, fetch or run anything beside that.
fn servers(application: &str, value: &Value) -> Checked {
    let held = members(value, &["mcpServers"], "the server file")?;
    let Some(Value::Object(servers)) = held.get("mcpServers") else {
        return Err("the server file has no mcpServers object".to_owned());
    };
    for server in servers.values() {
        let held = members(server, &["type", "command", "args"], "a server")?;
        if held.get("type").is_some_and(|kind| kind != "stdio")
            || !held.get("command").is_some_and(is_text)
        {
            return Err("a server is not one that starts a program with a command".to_owned());
        }
        if let Some(command) = held.get("command") {
            placeholder_form(application, command, held.get("args"))?;
        }
    }
    Ok(())
}

/// Whether this host registers the forwarder for the application as a line a shell runs. Gemini CLI
/// runs a handler's command as one line, and a program it starts is a word of that line. The others
/// are registered as a program with its arguments in a list beside it, and Claude Code's server file
/// is the only server file there is.
fn runs_a_line(application: &str) -> bool {
    application == "Gemini CLI"
}

/// Checks that a command that starts with the forwarder's placeholder is in the form this host
/// registers the forwarder in for its application. The host writes the forwarder's path for the
/// form the command is written in, one word in single quotes in a line and the plain path in a
/// program's name, so the other form would hand a shell an unquoted path, or a program a name that
/// is not one.
fn placeholder_form(application: &str, command: &Value, arguments: Option<&Value>) -> Checked {
    if !command
        .as_str()
        .is_some_and(|command| command.starts_with(kr_plugin_sdk::forwarder::PLACEHOLDER))
    {
        return Ok(());
    }
    let line = runs_a_line(application);
    if line == arguments.is_some() {
        let (written, registered) = if line {
            (
                "a program with its arguments in a list",
                "one line a shell runs",
            )
        } else {
            ("one line", "a program with its arguments in a list")
        };
        return Err(format!(
            "the forwarder is written as {written}, and this host registers it for {application} \
             as {registered}"
        ));
    }
    Ok(())
}

/// A hooks file: events, each a list of groups, each group an optional matcher and a list of
/// handlers, each handler a command: the kind `command`, its command, and its name, arguments and
/// time limit. A handler of another kind, which calls a tool or posts to an address, is not one.
fn hooks(application: &str, value: &Value) -> Checked {
    let held = members(value, &["hooks"], "the hooks file")?;
    let Some(Value::Object(events)) = held.get("hooks") else {
        return Err("the hooks file has no hooks object".to_owned());
    };
    for groups in events.values() {
        let Value::Array(groups) = groups else {
            return Err("an event is not a list of groups".to_owned());
        };
        for group in groups {
            let held = members(group, &["matcher", "hooks"], "a hook group")?;
            if held.get("matcher").is_some_and(|matcher| !is_text(matcher)) {
                return Err("a hook group's matcher is not text".to_owned());
            }
            let Some(Value::Array(handlers)) = held.get("hooks") else {
                return Err("a hook group has no list of handlers".to_owned());
            };
            for handler in handlers {
                let held = members(
                    handler,
                    &["type", "name", "command", "args", "timeout"],
                    "a handler",
                )?;
                let fits = held.get("type").is_some_and(|kind| kind == "command")
                    && held.get("command").is_some_and(is_text)
                    && held.get("name").is_none_or(is_text)
                    && held.get("args").is_none_or(|args| {
                        args.as_array().is_some_and(|args| args.iter().all(is_text))
                    })
                    && held.get("timeout").is_none_or(Value::is_number);
                if !fits {
                    return Err("a handler is not a command this host names".to_owned());
                }
                if let Some(command) = held.get("command") {
                    placeholder_form(application, command, held.get("args"))?;
                }
            }
        }
    }
    Ok(())
}

/// An extension's install record: where it was installed from, a local source that leads nowhere,
/// `/dev/null/<directory>`, so that the application has nothing to update it from and an
/// allowed-extensions pattern sees the name the directory has.
fn record(value: &Value, directory: &str) -> Checked {
    let held = members(value, &["source", "type"], "the install record")?;
    if held.get("type").is_some_and(|kind| kind == "local")
        && held.get("source").and_then(Value::as_str)
            == Some(format!("/dev/null/{directory}").as_str())
    {
        Ok(())
    } else {
        Err(format!(
            "the install record is not a local one with the source /dev/null/{directory}"
        ))
    }
}
