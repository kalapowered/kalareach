//! GNOME Terminal and Ptyxis: a profile is a set of keys in the settings database, named by a
//! uuid that is added to a list the application reads to find its profiles.
//!
//! Everything goes through the `gsettings` program, so the backend the person has (dconf, or a
//! keyfile) is the one written. The profile's own keys belong to kr; the list is shared with the
//! application's preferences window and with anything else that edits it, and the settings
//! database has no compare-and-set. A write of the list is therefore read before, read again just
//! before, written, and read back by another process; any change in between, and any element
//! missing afterwards, starts it over, up to a bound. Two interleavings remain, and both are named
//! limits. Another writer landing between the last read and the write is overwritten by it: an
//! element it added is lost from the list, or one it took out comes back. And a writer working
//! from a read it made before this one wrote, landing after the read back, can overwrite the list
//! and cost the profile its entry in it (or, in a removal, put the identifier back). The profile's
//! keys are kr's own and survive both, and a removal takes the keys of an unlisted profile out.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::record::{RecordedKey, RecordedList, SettingsWrote};
use super::{PROFILE_NAME, ProfileError, ProfileTerminal};

/// How long one `gsettings` call may take. A host with no settings service can wait for one.
const CALL_LIMIT: Duration = Duration::from_secs(15);

/// How many times a write of the shared list starts over before it gives up.
const ATTEMPTS: usize = 5;

/// How `gsettings` is run: the program, and the variables set for it beyond the process's own.
#[derive(Clone, Debug)]
pub struct Gsettings {
    /// The program.
    pub program: PathBuf,
    /// The variables it is run with, set over the process's own.
    pub environment: Vec<(String, String)>,
}

impl Gsettings {
    /// `gsettings` as the person's own session runs it.
    #[must_use]
    pub fn of_this_session() -> Self {
        Self {
            program: PathBuf::from("gsettings"),
            environment: Vec::new(),
        }
    }

    /// Runs the program with `arguments`, and returns what it printed on success, or why it did
    /// not.
    fn run(&self, arguments: &[&str]) -> Result<String, ToolFailure> {
        let mut command = Command::new(&self.program);
        command
            .args(arguments)
            .envs(self.environment.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| ToolFailure::Missing)?;
        // What the program prints is read as it runs: one that prints more than a pipe holds would
        // otherwise wait for a reader until its limit.
        let reader = child.stdout.take().map(|mut stdout| {
            std::thread::spawn(move || {
                use std::io::Read as _;
                let mut printed = Vec::new();
                let _ = stdout.read_to_end(&mut printed);
                printed
            })
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < CALL_LIMIT => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ToolFailure::Failed(None));
                }
            }
        };
        let printed = reader
            .and_then(|reader| reader.join().ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        if status.success() {
            Ok(printed.trim().to_owned())
        } else {
            Err(ToolFailure::Failed(status.code()))
        }
    }

    /// One key's value, in the text `gsettings` prints it in. `target` is a schema, or a schema and
    /// a path for a schema that is not at one place.
    fn get(&self, target: &str, key: &str) -> Result<String, ToolFailure> {
        self.run(&["get", target, key])
    }

    fn set(&self, target: &str, key: &str, value: &str) -> Result<(), ToolFailure> {
        self.run(&["set", target, key, value]).map(|_| ())
    }

    fn reset(&self, target: &str, key: &str) -> Result<(), ToolFailure> {
        self.run(&["reset", target, key]).map(|_| ())
    }

    /// The schemas the database knows: those with a place of their own, and the relocatable ones a
    /// profile's keys are, which `list-schemas` leaves out.
    fn schemas(&self) -> Result<Vec<String>, ToolFailure> {
        let mut known = Vec::new();
        for listing in ["list-schemas", "list-relocatable-schemas"] {
            known.extend(
                self.run(&[listing])?
                    .lines()
                    .map(|line| line.trim().to_owned()),
            );
        }
        Ok(known)
    }

    /// Every key of a schema at a path, with its value, in the text `gsettings` prints values in:
    /// one call for the whole profile.
    fn dump(&self, target: &str) -> Result<Vec<(String, String)>, ToolFailure> {
        Ok(self
            .run(&["list-recursively", target])?
            .lines()
            .filter_map(|line| {
                // `schema key value`, the value being the rest of the line.
                let mut parts = line.splitn(3, ' ');
                let (_, key, value) = (parts.next()?, parts.next()?, parts.next()?);
                Some((key.to_owned(), value.to_owned()))
            })
            .collect())
    }
}

/// Why a call to `gsettings` came to nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolFailure {
    /// The program is not there.
    Missing,
    /// It ran and failed, or ran past its limit; the exit status where it had one.
    Failed(Option<i32>),
}

/// What differs between the two applications that keep their profiles in settings.
#[derive(Clone, Copy, Debug)]
pub(super) struct Spec {
    pub terminal: ProfileTerminal,
    /// The schema of the shared list, which also holds the application's default.
    pub list_schema: &'static str,
    /// The key of the list of profiles.
    pub list_key: &'static str,
    /// The key of the default profile.
    pub default_key: &'static str,
    /// The schema of one profile's keys.
    pub profile_schema: &'static str,
    /// The path of one profile's keys, from its identifier.
    pub profile_path: fn(&str) -> String,
    /// The key of the profile's name.
    pub name_key: &'static str,
    /// The key that makes the profile run a command.
    pub custom_flag_key: &'static str,
    /// The key of the command.
    pub command_key: &'static str,
    /// An identifier of the kind the application makes.
    pub new_identifier: fn() -> String,
}

/// GNOME Terminal.
pub(super) const GNOME: Spec = Spec {
    terminal: ProfileTerminal::GnomeTerminal,
    list_schema: "org.gnome.Terminal.ProfilesList",
    list_key: "list",
    default_key: "default",
    profile_schema: "org.gnome.Terminal.Legacy.Profile",
    profile_path: |uuid| format!("/org/gnome/terminal/legacy/profiles:/:{uuid}/"),
    name_key: "visible-name",
    custom_flag_key: "use-custom-command",
    command_key: "custom-command",
    new_identifier: || kr_ipc::new_uuid().to_string(),
};

/// Ptyxis.
pub(super) const PTYXIS: Spec = Spec {
    terminal: ProfileTerminal::Ptyxis,
    list_schema: "org.gnome.Ptyxis",
    list_key: "profile-uuids",
    default_key: "default-profile-uuid",
    profile_schema: "org.gnome.Ptyxis.Profile",
    profile_path: |uuid| format!("/org/gnome/Ptyxis/Profiles/{uuid}/"),
    name_key: "label",
    custom_flag_key: "use-custom-command",
    command_key: "custom-command",
    new_identifier: || kr_ipc::new_uuid().to_string().replace('-', ""),
};

/// A path no profile is at, whose keys all read their defaults.
fn unused_path(spec: &Spec) -> String {
    (spec.profile_path)("00000000-0000-0000-0000-000000000000")
}

/// A string as GVariant text writes it.
#[must_use]
pub(super) fn variant_string(value: &str) -> String {
    let mut text = String::with_capacity(value.len() + 2);
    text.push('\'');
    for character in value.chars() {
        match character {
            '\\' => text.push_str(r"\\"),
            '\'' => text.push_str(r"\'"),
            '\n' => text.push_str(r"\n"),
            '\t' => text.push_str(r"\t"),
            '\r' => text.push_str(r"\r"),
            other => text.push(other),
        }
    }
    text.push('\'');
    text
}

/// The string a GVariant text of a string value holds, in either of the quotes `gsettings` prints
/// it in, or `None` for text that is not one.
#[must_use]
pub(super) fn parse_string(text: &str) -> Option<String> {
    let text = text.trim();
    let text = text.strip_prefix("@s ").unwrap_or(text);
    let mut characters = text.chars();
    let quote = characters
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))?;
    let mut value = String::new();
    loop {
        match characters.next()? {
            character if character == quote => {
                return characters.next().is_none().then_some(value);
            }
            '\\' => value.push(match characters.next()? {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            }),
            other => value.push(other),
        }
    }
}

/// The strings in the text of an array of strings, or `None` for text that is not one.
#[must_use]
pub(super) fn parse_strings(text: &str) -> Option<Vec<String>> {
    let text = text.trim();
    let text = text.strip_prefix("@as ").unwrap_or(text);
    let inner = text.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut strings = Vec::new();
    let mut characters = inner.char_indices().peekable();
    while characters.peek().is_some() {
        let (start, quote) = characters.next()?;
        if !matches!(quote, '\'' | '"') {
            return None;
        }
        let mut end = None;
        while let Some((index, character)) = characters.next() {
            if character == '\\' {
                characters.next();
            } else if character == quote {
                end = Some(index);
                break;
            }
        }
        strings.push(parse_string(&inner[start..=end?])?);
        // Between two strings there is a comma, and nothing after the last.
        match characters.next() {
            None => break,
            Some((_, ',')) => {
                while characters
                    .next_if(|(_, character)| *character == ' ')
                    .is_some()
                {}
            }
            Some(_) => return None,
        }
    }
    Some(strings)
}

/// An array of strings as GVariant text writes it.
fn variant_strings(strings: &[String]) -> String {
    format!(
        "[{}]",
        strings
            .iter()
            .map(|string| variant_string(string))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Whether two values read from `gsettings` are one value: strings by what they hold, anything
/// else by its text.
fn same_value(left: &str, right: &str) -> bool {
    match (parse_string(left), parse_string(right)) {
        (Some(left), Some(right)) => left == right,
        _ => left.trim() == right.trim(),
    }
}

fn tool(failure: ToolFailure, spec: &Spec) -> ProfileError {
    match failure {
        ToolFailure::Missing => ProfileError::ToolMissing(spec.terminal),
        ToolFailure::Failed(status) => ProfileError::ToolFailed {
            terminal: spec.terminal,
            status,
        },
    }
}

/// The identifiers in the shared list, in order.
fn profiles(gsettings: &Gsettings, spec: &Spec) -> Result<Vec<String>, ProfileError> {
    let text = gsettings
        .get(spec.list_schema, spec.list_key)
        .map_err(|failure| tool(failure, spec))?;
    parse_strings(&text).ok_or(ProfileError::ToolFailed {
        terminal: spec.terminal,
        status: None,
    })
}

/// The application's default profile.
fn default_profile(gsettings: &Gsettings, spec: &Spec) -> Result<String, ProfileError> {
    let text = gsettings
        .get(spec.list_schema, spec.default_key)
        .map_err(|failure| tool(failure, spec))?;
    parse_string(&text).ok_or(ProfileError::ToolFailed {
        terminal: spec.terminal,
        status: None,
    })
}

/// What one profile in the list is named.
fn name_of(gsettings: &Gsettings, spec: &Spec, uuid: &str) -> Option<String> {
    let target = format!("{}:{}", spec.profile_schema, (spec.profile_path)(uuid));
    gsettings
        .get(&target, spec.name_key)
        .ok()
        .and_then(|text| parse_string(&text))
}

/// What installing a profile into settings would write, worked out before anything is.
#[derive(Clone, Debug)]
pub(super) struct SettingsPlan {
    pub spec: Spec,
    pub gsettings: Gsettings,
    pub uuid: String,
    pub wrote: SettingsWrote,
    /// Every value kr recorded for the profile's keys earlier: what it wrote, and what the profile
    /// held before an install again that could not take itself back. A key that holds one of them,
    /// or nothing, is kr's to write; any other value is the person's.
    pub known: Vec<RecordedKey>,
    /// Whether the profile is already in the shared list, so that a failed write leaves it there.
    pub listed_before: bool,
}

/// Works out the install, and refuses what it must not write beside.
///
/// # Errors
///
/// Returns why the profile is not written.
pub(super) fn plan(
    gsettings: &Gsettings,
    spec: Spec,
    command_text: &str,
    recorded: Option<&SettingsWrote>,
) -> Result<SettingsPlan, ProfileError> {
    let terminal = spec.terminal;
    let schemas = gsettings
        .schemas()
        .map_err(|failure| tool(failure, &spec))?;
    if !schemas.iter().any(|schema| schema == spec.list_schema)
        || !schemas.iter().any(|schema| schema == spec.profile_schema)
    {
        return Err(ProfileError::SchemaAbsent(terminal));
    }
    let list = profiles(gsettings, &spec)?;
    let default = default_profile(gsettings, &spec)?;
    // A list with no default, or a default that is not in it, is one the application settles by
    // taking the first profile in it: ours could become the default by that alone.
    if list.is_empty() || !list.contains(&default) {
        return Err(ProfileError::NoDefaultProfile(terminal));
    }
    let uuid = recorded.map_or_else(
        || (spec.new_identifier)(),
        |recorded| recorded.list.member.clone(),
    );
    if let Some(recorded) = recorded
        && recorded.schema != spec.profile_schema
    {
        return Err(ProfileError::RecordedOtherwise(terminal));
    }
    // A profile of the person's own with our name makes the application's own way of choosing a
    // profile by name ambiguous.
    for other in list.iter().filter(|other| **other != uuid) {
        if name_of(gsettings, &spec, other).is_some_and(|name| name == PROFILE_NAME) {
            return Err(ProfileError::ForeignProfile(terminal));
        }
    }
    let wrote = SettingsWrote {
        schema: spec.profile_schema.to_owned(),
        path: (spec.profile_path)(&uuid),
        keys: vec![
            RecordedKey {
                key: spec.name_key.to_owned(),
                value: variant_string(PROFILE_NAME),
            },
            RecordedKey {
                key: spec.custom_flag_key.to_owned(),
                value: "true".to_owned(),
            },
            RecordedKey {
                key: spec.command_key.to_owned(),
                value: variant_string(command_text),
            },
        ],
        list: RecordedList {
            schema: spec.list_schema.to_owned(),
            key: spec.list_key.to_owned(),
            member: uuid.clone(),
        },
        earlier: None,
    };
    let listed_before = list.contains(&uuid);
    Ok(SettingsPlan {
        spec,
        gsettings: gsettings.clone(),
        uuid,
        wrote,
        known: recorded.map_or_else(Vec::new, known_values),
        listed_before,
    })
}

/// What a profile's keys hold now, and what each key reads when it is not set.
struct Held {
    values: Vec<(String, String)>,
    defaults: Vec<(String, String)>,
}

impl Held {
    /// Reads the profile at `schema` and `path` in one pass.
    fn of(
        gsettings: &Gsettings,
        spec: &Spec,
        schema: &str,
        path: &str,
    ) -> Result<Self, ProfileError> {
        Ok(Self {
            values: gsettings
                .dump(&format!("{schema}:{path}"))
                .map_err(|failure| tool(failure, spec))?,
            defaults: gsettings
                .dump(&format!("{schema}:{}", unused_path(spec)))
                .map_err(|failure| tool(failure, spec))?,
        })
    }

    fn value(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    fn default(&self, key: &str) -> Option<&str> {
        self.defaults
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// Whether `value` is what the key reads when it is not set.
    fn is_unset(&self, key: &str, value: &str) -> bool {
        self.default(key)
            .is_some_and(|default| same_value(value, default))
    }

    /// Whether every key of the profile that kr did not write is at its default: a font or a colour
    /// the person set is theirs, and a profile that holds one is not kr's to write over or take out.
    fn others_unset(&self, kr_keys: &[RecordedKey]) -> bool {
        self.values
            .iter()
            .filter(|(key, _)| !kr_keys.iter().any(|written| written.key == *key))
            .all(|(key, value)| self.is_unset(key, value))
    }

    /// The value the key held when this was read, or `None` where it was not set.
    fn was(&self, key: &str) -> Option<&str> {
        self.value(key).filter(|value| !self.is_unset(key, value))
    }

    /// Puts one key back to what it held when this was read, and says whether it is back, read by
    /// another process. `kr_state` is what kr left in the key: a value it wrote, or `None` for a
    /// reset. A key that holds neither that nor what it held before is another writer's, changed
    /// since kr wrote it: it is left, and nothing of kr's is in it, so it counts as back. A key
    /// that cannot be read is not written, and does not count as back.
    fn restore(
        &self,
        gsettings: &Gsettings,
        target: &str,
        key: &str,
        kr_state: Option<&str>,
    ) -> bool {
        let Ok(now) = gsettings.get(target, key) else {
            return false;
        };
        let was = self.was(key);
        let kept = match kr_state {
            Some(wrote) => same_value(&now, wrote),
            None => self.is_unset(key, &now),
        };
        let already = match was {
            Some(was) => same_value(&now, was),
            None => self.is_unset(key, &now),
        };
        if already {
            return true;
        }
        if !kept {
            return true;
        }
        match was {
            Some(was) => {
                gsettings.set(target, key, was).is_ok()
                    && gsettings
                        .get(target, key)
                        .is_ok_and(|read| same_value(&read, was))
            }
            None => {
                gsettings.reset(target, key).is_ok()
                    && gsettings.get(target, key).is_ok_and(|read| {
                        self.default(key)
                            .is_some_and(|default| same_value(&read, default))
                    })
            }
        }
    }

    /// Whether `value` is one kr may write over or take out: the key is not set, or it holds one of
    /// `known`, or `also`.
    fn is_kr_s(&self, key: &str, value: &str, known: &[RecordedKey], also: Option<&str>) -> bool {
        self.is_unset(key, value)
            || also.is_some_and(|also| same_value(value, also))
            || known
                .iter()
                .any(|recorded| recorded.key == key && same_value(value, &recorded.value))
    }
}

/// Every value kr recorded for the keys of a profile.
fn known_values(wrote: &SettingsWrote) -> Vec<RecordedKey> {
    wrote
        .keys
        .iter()
        .chain(wrote.earlier.iter().flatten())
        .cloned()
        .collect()
}

/// Carries out the plan: the profile's keys first, then its place in the shared list, and a read
/// back by another process of both. Before a key changes it is read again, and it must hold what
/// the read before the first write showed; a profile the person changed since is left as it is and
/// the write stops. A write that does not hold takes itself back: the keys it changed go back to
/// what they held, each read back to be sure, and the profile leaves the list unless it was in it
/// before.
///
/// # Errors
///
/// Returns why the profile is not written and whether anything of it may be left that could not be
/// taken back, which the caller then keeps the record's entry for, so that a removal can finish
/// the job.
pub(super) fn write(plan: &SettingsPlan) -> Result<(), (ProfileError, bool)> {
    let spec = &plan.spec;
    let gsettings = &plan.gsettings;
    let target = format!("{}:{}", plan.wrote.schema, plan.wrote.path);
    // What the profile holds now. Nothing has been written, so a failure here leaves nothing.
    let held = Held::of(gsettings, spec, &plan.wrote.schema, &plan.wrote.path)
        .map_err(|error| (error, false))?;
    let changed = || ProfileError::Changed {
        place: PathBuf::from(&plan.wrote.path),
    };
    for key in &plan.wrote.keys {
        let kept = held
            .value(&key.key)
            .is_some_and(|value| held.is_kr_s(&key.key, value, &plan.known, Some(&key.value)));
        if !kept {
            return Err((changed(), false));
        }
    }
    // A key kr does not write that the person set (a font, a colour) makes the profile theirs: it
    // is read again just before the first key is set, and either read finding one stops the write.
    let again = Held::of(gsettings, spec, &plan.wrote.schema, &plan.wrote.path)
        .map_err(|error| (error, false))?;
    if !held.others_unset(&plan.wrote.keys) || !again.others_unset(&plan.wrote.keys) {
        return Err((changed(), false));
    }
    // Puts back the keys written so far, and says whether each is back (see `Held::restore`). A key
    // that cannot be put back does not stop the others.
    let undo = |written: &[RecordedKey]| {
        let mut all_back = true;
        for key in written {
            all_back &= held.restore(gsettings, &target, &key.key, Some(&key.value));
        }
        all_back
    };
    let mut written: Vec<RecordedKey> = Vec::new();
    for key in &plan.wrote.keys {
        // Just before the key changes: still what the read showed, or the person changed it.
        let unchanged = match gsettings.get(&target, &key.key) {
            Ok(now) => held
                .value(&key.key)
                .is_some_and(|seen| same_value(&now, seen)),
            Err(failure) => return Err((tool(failure, spec), !undo(&written))),
        };
        if !unchanged {
            return Err((changed(), !undo(&written)));
        }
        written.push(key.clone());
        if let Err(failure) = gsettings.set(&target, &key.key, &key.value) {
            return Err((tool(failure, spec), !undo(&written)));
        }
    }
    // Read back by a process of its own: a backend that keeps a write only in the process that
    // made it (a session with no settings service) shows nothing here.
    for key in &plan.wrote.keys {
        let kept = match gsettings.get(&target, &key.key) {
            Ok(read) if same_value(&read, &key.value) => true,
            // The key reads as it did before the write: the write was not kept. Anything else was
            // put there by another writer since.
            Ok(read) => {
                let unkept = match held.was(&key.key) {
                    Some(was) => same_value(&read, was),
                    None => held.is_unset(&key.key, &read),
                };
                let error = if unkept {
                    ProfileError::NotPersisted(spec.terminal)
                } else {
                    changed()
                };
                return Err((error, !undo(&written)));
            }
            Err(_) => false,
        };
        if !kept {
            return Err((ProfileError::NotPersisted(spec.terminal), !undo(&written)));
        }
    }
    if let Err(error) = change_list(gsettings, spec, &plan.uuid, true) {
        // The write of the list may have landed before it failed to read back: the identifier is
        // taken out again, unless it was in the list before this write, and if that fails too the
        // caller keeps the record's entry.
        let cleaned = plan.listed_before || change_list(gsettings, spec, &plan.uuid, false).is_ok();
        let restored = undo(&written);
        return Err((error, !(cleaned && restored)));
    }
    Ok(())
}

/// Adds `member` to the shared list, or takes it out, and checks that it held.
///
/// The list is read, read again just before it is written, and written; it is then read by
/// another process. A change between the two reads, a pre-write element missing afterwards or the
/// change itself missing starts it over, up to a bound.
fn change_list(
    gsettings: &Gsettings,
    spec: &Spec,
    member: &str,
    adding: bool,
) -> Result<(), ProfileError> {
    for _ in 0..ATTEMPTS {
        let before = profiles(gsettings, spec)?;
        let has = before.iter().any(|existing| existing == member);
        if has == adding {
            // Already as wanted, as another writer's list may have it: check once more by
            // another process that it still is.
            let again = profiles(gsettings, spec)?;
            if again.iter().any(|existing| existing == member) == adding {
                return Ok(());
            }
            continue;
        }
        let just_before = profiles(gsettings, spec)?;
        if just_before != before {
            continue;
        }
        let mut after = before.clone();
        if adding {
            after.push(member.to_owned());
        } else {
            after.retain(|existing| existing != member);
        }
        gsettings
            .set(spec.list_schema, spec.list_key, &variant_strings(&after))
            .map_err(|failure| tool(failure, spec))?;
        let read_back = profiles(gsettings, spec)?;
        let kept = before
            .iter()
            .filter(|existing| existing.as_str() != member)
            .all(|existing| read_back.contains(existing));
        let changed = read_back.iter().any(|existing| existing == member) == adding;
        if kept && changed {
            return Ok(());
        }
    }
    Err(ProfileError::ListBusy(spec.terminal))
}

/// Where a recorded profile stands in settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reading {
    /// Every key kr wrote has its value and every other key of the profile is at its default.
    Unchanged { in_list: bool },
    /// No key of the profile is set and it is not in the list.
    Gone,
    /// Something else.
    Changed,
}

/// Reads where a recorded profile stands.
///
/// Every key kr wrote must have the value it wrote and every other key of the profile must be
/// unset, or the profile has changed. A profile that is not in the list the application reads is
/// out of the person's sight, and one whose keys are some of kr's and the rest unset (an install
/// or a removal that was cut short) is read as unchanged, so that a removal can finish it.
///
/// # Errors
///
/// Returns the failure of `gsettings`: a profile that cannot be read is not one that has changed or
/// is gone.
pub(super) fn read(
    gsettings: &Gsettings,
    spec: Spec,
    wrote: &SettingsWrote,
) -> Result<Reading, ProfileError> {
    // The schemas the keys are read through: without them nothing can be read, and a profile whose
    // application was uninstalled is not one that has gone.
    let schemas = gsettings
        .schemas()
        .map_err(|failure| tool(failure, &spec))?;
    if !schemas.iter().any(|schema| *schema == spec.list_schema)
        || !schemas.iter().any(|schema| *schema == spec.profile_schema)
    {
        return Err(ProfileError::SchemaAbsent(spec.terminal));
    }
    let target = format!("{}:{}", wrote.schema, wrote.path);
    let unused = format!("{}:{}", wrote.schema, unused_path(&spec));
    let in_list = profiles(gsettings, &spec)?.contains(&wrote.list.member);
    let values = gsettings
        .dump(&target)
        .map_err(|failure| tool(failure, &spec))?;
    let defaults = gsettings
        .dump(&unused)
        .map_err(|failure| tool(failure, &spec))?;
    let mut ours_match = true;
    let mut ours_default = true;
    let mut ours_kr_s_or_unset = true;
    let mut others_default = true;
    for (key, value) in &values {
        let unset = defaults
            .iter()
            .find(|(other, _)| other == key)
            .is_some_and(|(_, default)| same_value(value, default));
        match wrote.keys.iter().find(|written| written.key == *key) {
            Some(written) => {
                // What kr wrote, or what the profile held before an install again that could not
                // take itself back.
                let ours =
                    same_value(value, &written.value)
                        || wrote.earlier.iter().flatten().any(|earlier| {
                            earlier.key == *key && same_value(value, &earlier.value)
                        });
                ours_match &= ours;
                ours_default &= unset;
                ours_kr_s_or_unset &= ours || unset;
            }
            None => others_default &= unset,
        }
    }
    // A key kr wrote that the schema does not list is one that is not kept.
    for written in &wrote.keys {
        if !values.iter().any(|(key, _)| *key == written.key) {
            ours_match = false;
            ours_default = false;
            ours_kr_s_or_unset = false;
        }
    }
    Ok(if ours_default && others_default {
        // Nothing of the profile's own is set: gone, unless its place in the list is left over,
        // which a removal takes out.
        if in_list {
            Reading::Unchanged { in_list }
        } else {
            Reading::Gone
        }
    } else if others_default && (ours_match || (!in_list && ours_kr_s_or_unset)) {
        Reading::Unchanged { in_list }
    } else {
        Reading::Changed
    })
}

/// Whether the recorded profile is the application's default.
///
/// # Errors
///
/// Returns the failure of `gsettings`: what cannot be read is not taken to be no default.
pub(super) fn is_default(
    gsettings: &Gsettings,
    spec: Spec,
    wrote: &SettingsWrote,
) -> Result<bool, ProfileError> {
    Ok(default_profile(gsettings, &spec)? == wrote.list.member)
}

/// What taking a profile out came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TakenOut {
    /// Its keys are reset and it is out of the list.
    Removed,
    /// A key holds something the person put there, and is left as it is.
    Changed,
}

/// Takes an unchanged profile out: its identifier leaves the shared list and its keys are reset.
/// Every key is read before the first write and again just before it is reset. One that holds a
/// value the person put there stops the removal: the keys already reset and the place in the list
/// (if the profile was in it) are put back, and the profile is left as it was. `in_list` says
/// whether it was. Each reset is read back by another process: a
/// key that still holds its value is a failure.
///
/// # Errors
///
/// Returns why it could not be; what was reset stays reset, and the caller keeps the record's
/// entry.
pub(super) fn take_out(
    gsettings: &Gsettings,
    spec: Spec,
    wrote: &SettingsWrote,
    in_list: bool,
) -> Result<TakenOut, ProfileError> {
    let target = format!("{}:{}", wrote.schema, wrote.path);
    let known = known_values(wrote);
    let held = Held::of(gsettings, &spec, &wrote.schema, &wrote.path)?;
    let ours = |key: &str, value: &str| held.is_kr_s(key, value, &known, None);
    // Every key of the profile is read, not only the three kr wrote: a font or a colour the person
    // set makes the profile theirs.
    if !held.others_unset(&wrote.keys)
        || wrote.keys.iter().any(|key| {
            !held
                .value(&key.key)
                .is_some_and(|value| ours(&key.key, value))
        })
    {
        return Ok(TakenOut::Changed);
    }
    // The list first: a profile out of the list and with its keys set is invisible, where one in
    // the list with its keys reset would be shown unnamed.
    change_list(gsettings, &spec, &wrote.list.member, false)?;
    let mut reset: Vec<&RecordedKey> = Vec::new();
    // Puts back what this removal changed so far: the keys it reset, and the place in the list if
    // the profile was in it. A key that holds something the person put there is left (see
    // `Held::restore`). Says whether everything is back.
    let put_back = |reset: &[&RecordedKey]| {
        let mut back = true;
        for earlier in reset {
            back &= held.restore(gsettings, &target, &earlier.key, None);
        }
        if in_list {
            back &= change_list(gsettings, &spec, &wrote.list.member, true).is_ok();
        }
        back
    };
    // The profile is read again now that it is out of the list: a key kr does not write that the
    // person set since the first read makes it theirs.
    let again = Held::of(gsettings, &spec, &wrote.schema, &wrote.path)?;
    if !again.others_unset(&wrote.keys) {
        return if put_back(&reset) {
            Ok(TakenOut::Changed)
        } else {
            Err(ProfileError::Changing(spec.terminal))
        };
    }
    for key in &wrote.keys {
        let now = gsettings
            .get(&target, &key.key)
            .map_err(|failure| tool(failure, &spec))?;
        if !ours(&key.key, &now) {
            // The person changed this key since the read above. The profile is theirs now, so the
            // profile goes back as it was: its place in the list, and the keys already reset. Only
            // when it is back is it left, with nothing recorded.
            return if put_back(&reset) {
                Ok(TakenOut::Changed)
            } else {
                Err(ProfileError::Changing(spec.terminal))
            };
        }
        reset.push(key);
        gsettings
            .reset(&target, &key.key)
            .map_err(|failure| tool(failure, &spec))?;
        let after = gsettings
            .get(&target, &key.key)
            .map_err(|failure| tool(failure, &spec))?;
        if held
            .default(&key.key)
            .is_some_and(|default| same_value(&after, default))
        {
            continue;
        }
        // Not the default after a reset: either the reset was not kept (the key still holds what
        // it held), or another writer set it since. The first is a settings service that does not
        // keep its resets; the second is the person's edit, which is left, with what this removal
        // changed put back, and the record kept.
        let unkept = held
            .value(&key.key)
            .is_some_and(|value| same_value(&after, value));
        if unkept {
            return Err(ProfileError::NotPersisted(spec.terminal));
        }
        reset.pop();
        put_back(&reset);
        return Err(ProfileError::Changing(spec.terminal));
    }
    Ok(TakenOut::Removed)
}

/// Whether a profile of the person's own is in the list under this one's name.
pub(super) fn foreign(gsettings: &Gsettings, spec: Spec) -> bool {
    profiles(gsettings, &spec).is_ok_and(|list| {
        list.iter()
            .any(|uuid| name_of(gsettings, &spec, uuid).is_some_and(|name| name == PROFILE_NAME))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GVariant text of strings: written with a quote and a backslash escaped, and read back from
    /// either quote `gsettings` prints.
    #[test]
    fn variant_text_of_a_string_round_trips() {
        for text in [
            "plain",
            "it's",
            r"a\b",
            "two\nlines",
            "a \"quoted\" word",
            "caf\u{e9}",
        ] {
            assert_eq!(parse_string(&variant_string(text)).as_deref(), Some(text));
        }
        assert_eq!(parse_string(r#""it's""#).as_deref(), Some("it's"));
        assert_eq!(parse_string("@s 'x'").as_deref(), Some("x"));
        assert_eq!(parse_string("true"), None);
        assert_eq!(parse_string("'unterminated"), None);
    }

    /// An array of strings, empty or not, as `gsettings` prints it.
    #[test]
    fn variant_text_of_an_array_of_strings_is_read() {
        assert_eq!(parse_strings("@as []"), Some(Vec::new()));
        assert_eq!(parse_strings("[]"), Some(Vec::new()));
        assert_eq!(
            parse_strings("['b1dcc9dd', 'it\\'s', \"two\"]"),
            Some(vec![
                "b1dcc9dd".to_owned(),
                "it's".to_owned(),
                "two".to_owned()
            ])
        );
        assert_eq!(parse_strings("[1, 2]"), None);
        assert_eq!(parse_strings("'x'"), None);
        let strings = vec!["a".to_owned(), "it's".to_owned()];
        assert_eq!(parse_strings(&variant_strings(&strings)), Some(strings));
    }

    /// KR-REQ-01.21: a key that cannot be read is not written back, because whether it holds kr's
    /// value is not known: `gsettings` is run, and no `set` or `reset` reaches it.
    #[cfg(unix)]
    #[test]
    fn a_key_that_cannot_be_read_is_not_written_back() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = std::env::temp_dir().join(format!("kr-gsettings-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let program = directory.join("gsettings");
        let log = directory.join("calls");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"$1\" >> '{}'\n[ \"$1\" = get ] && exit 1\nexit 0\n",
                log.display()
            ),
        )
        .expect("a program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        let gsettings = Gsettings {
            program,
            environment: Vec::new(),
        };
        let held = Held {
            values: vec![("custom-command".to_owned(), "'/bin/kr'".to_owned())],
            defaults: vec![("custom-command".to_owned(), "''".to_owned())],
        };
        assert!(!held.restore(
            &gsettings,
            "schema:/path/",
            "custom-command",
            Some("'/bin/x'")
        ));
        let calls = std::fs::read_to_string(&log).expect("the calls");
        assert!(
            calls.lines().all(|call| call == "get"),
            "only reads reached it: {calls}"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    /// Two readings of one string are one value whatever quotes they are printed in.
    #[test]
    fn the_same_string_in_the_two_quotes_is_one_value() {
        assert!(same_value("'/opt/it\\'s/kr'", "\"/opt/it's/kr\""));
        assert!(same_value("true", "true"));
        assert!(!same_value("'a'", "'b'"));
    }
}
