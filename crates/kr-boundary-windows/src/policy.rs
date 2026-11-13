//! The application-control policy the installation puts in force, and the one form every policy is
//! read back into.
//!
//! The policy covers the executable collection and nothing else. Three rules, each with a fixed
//! identifier so that an installation can find its own rules among an administrator's:
//!
//! - one lets every account start every program, so nobody but the boundary accounts is limited;
//! - one denies the checkout account every program but Git's own `git.exe`;
//! - one denies the connection account every program but Git, a short list of Git's own programs
//!   and the credential helper.
//!
//! [`Policy::render`] writes the policy for the platform's own tool to apply. [`Policy::parse`]
//! reads what the platform reports as the effective policy into the same [`Policy`] value, so that
//! "is this what we installed" is one equality and a difference can be named.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use quick_xml::Writer;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

/// The rule that lets every account start every program.
pub const RULE_ALLOW_ALL: &str = "b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01";
/// The rule that limits the checkout account to Git.
pub const RULE_CHECKOUT: &str = "b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a02";
/// The rule that limits the connection account to Git, its transport programs and the helper.
pub const RULE_CONNECT: &str = "b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a03";
/// The identifier of every account, the group the first rule is written for.
pub const EVERYONE: &str = "S-1-1-0";

/// The name of the collection of executable programs.
pub const EXE: &str = "Exe";

/// Where Git for Windows installs for every account, as the policy names it.
pub const GIT_DIR: &str = r"%PROGRAMFILES%\Git";
/// Where the installation puts the broker and the credential helper, as the policy names it.
pub const BOUNDARY_DIR: &str = r"%PROGRAMFILES%\KalaReach\Boundary";
/// The credential helper's own file name.
pub const HELPER: &str = "kr-boundary-credential.exe";

/// The programs the checkout account may start, relative to Git's installation.
pub const CHECKOUT_LIST: [&str; 1] = [r"mingw64\bin\git.exe"];

/// The programs the connection account may start beyond the checkout account's, relative to Git's
/// installation. The helper is named separately because it is not in Git's installation.
pub const CONNECT_EXTRA: [&str; 6] = [
    r"mingw64\libexec\git-core\git.exe",
    r"mingw64\libexec\git-core\git-remote-https.exe",
    r"mingw64\libexec\git-core\git-remote-http.exe",
    r"mingw64\bin\git-upload-pack.exe",
    r"usr\bin\sh.exe",
    r"usr\bin\ssh.exe",
];

/// Every program of Git's installation either account may start, relative to the installation.
#[must_use]
pub fn git_images() -> Vec<&'static str> {
    CHECKOUT_LIST
        .iter()
        .chain(CONNECT_EXTRA.iter())
        .copied()
        .collect()
}

/// Whether a rule allows or denies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// The rule allows what its conditions name.
    Allow,
    /// The rule denies what its conditions name, except its exceptions.
    Deny,
}

/// What a collection does with its rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// The collection enforces nothing.
    NotConfigured,
    /// The collection only records what it would have refused.
    AuditOnly,
    /// The collection refuses what its rules deny.
    Enabled,
}

/// How a rule names what it applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// By path: the only kind this installation writes.
    Path,
    /// By publisher.
    Publisher,
    /// By file hash.
    Hash,
}

/// One rule, in the form two policies are compared in: identifiers in lower case, paths in lower
/// case with backslashes, and the sets without order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The rule's identifier, lower case, without braces.
    pub id: String,
    /// How the rule names what it applies to.
    pub kind: Kind,
    /// The identifier of the account or group the rule is for, upper case.
    pub sid: String,
    /// Whether the rule allows or denies.
    pub action: Action,
    /// The paths the rule applies to.
    pub conditions: BTreeSet<String>,
    /// The paths a deny rule leaves out.
    pub exceptions: BTreeSet<String>,
}

/// One collection of rules and the way it is enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// How the collection is enforced.
    pub mode: Mode,
    /// The rules, by identifier.
    pub rules: BTreeMap<String, Rule>,
}

/// A policy: its collections by name. A collection a policy does not mention is not configured and
/// holds no rules.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// The collections, by the name the platform gives them (`Exe`, `Dll`, `Script`, `Msi`, `Appx`).
    pub collections: BTreeMap<String, Collection>,
}

/// Two policies are equal when no collection differs: one that is not configured and holds no
/// rule is the same as one the policy does not mention.
impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.differences(other).is_empty()
    }
}

impl Eq for Policy {}

/// A policy that could not be read.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The text is not a policy.
    // text: policy-1
    #[error("the text of the policy is not one that this program reads: {0}")]
    Unreadable(String),
    /// An entry of the policy lacks a field, or holds a value that this program does not know.
    // text: policy-2
    #[error("the policy holds an entry that this program does not understand: {0}")]
    Unknown(String),
}

fn normal_path(path: &str) -> String {
    path.trim().replace('/', "\\").to_lowercase()
}

fn normal_id(id: &str) -> String {
    id.trim().trim_matches(['{', '}']).to_lowercase()
}

/// Whether a normalised rule identifier is a GUID, as the platform writes one: five groups of
/// hexadecimal digits of 8, 4, 4, 4 and 12, joined by hyphens.
fn is_rule_id(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

/// Whether a part of a security identifier is a number in decimal digits alone, with no leading
/// zero, that is no more than `largest`.
fn is_number_up_to(part: &str, largest: u64) -> bool {
    // At most 15 digits, so the value cannot overflow.
    part.len() <= 15
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
        && !part.is_empty()
        && part
            .bytes()
            .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'))
            <= largest
}

/// Whether a normalised account identifier is a security identifier: `S-1-`, an authority of up to
/// 48 bits, and one to fifteen sub-authorities of up to 32 bits, each in decimal digits alone.
fn is_account_id(sid: &str) -> bool {
    let parts: Vec<&str> = sid.split('-').collect();
    let [prefix, revision, authority, subs @ ..] = parts.as_slice() else {
        return false;
    };
    *prefix == "S"
        && *revision == "1"
        && is_number_up_to(authority, (1 << 48) - 1)
        && (1..=15).contains(&subs.len())
        && subs
            .iter()
            .all(|sub| is_number_up_to(sub, u64::from(u32::MAX)))
}

impl Policy {
    /// The policy the installation puts in force for the two accounts.
    #[must_use]
    pub fn installed(checkout_sid: &str, connect_sid: &str) -> Policy {
        let git = |relative: &str| normal_path(&format!(r"{GIT_DIR}\{relative}"));
        let everything: BTreeSet<String> = BTreeSet::from(["*".to_owned()]);
        let helper = normal_path(&format!(r"{BOUNDARY_DIR}\{HELPER}"));
        let checkout: BTreeSet<String> = CHECKOUT_LIST.iter().map(|path| git(path)).collect();
        let mut connect: BTreeSet<String> = checkout.clone();
        connect.extend(CONNECT_EXTRA.iter().map(|path| git(path)));
        connect.insert(helper);
        let rule = |id: &str, sid: &str, action, exceptions: BTreeSet<String>| {
            (
                id.to_owned(),
                Rule {
                    id: id.to_owned(),
                    kind: Kind::Path,
                    sid: sid.to_uppercase(),
                    action,
                    conditions: everything.clone(),
                    exceptions,
                },
            )
        };
        let rules = BTreeMap::from([
            rule(RULE_ALLOW_ALL, EVERYONE, Action::Allow, BTreeSet::new()),
            rule(RULE_CHECKOUT, checkout_sid, Action::Deny, checkout),
            rule(RULE_CONNECT, connect_sid, Action::Deny, connect),
        ]);
        Policy {
            collections: BTreeMap::from([(
                EXE.to_owned(),
                Collection {
                    mode: Mode::Enabled,
                    rules,
                },
            )]),
        }
    }

    /// Whether the policy enforces nothing and holds no rule: the state a computer has before any
    /// application control is set.
    #[must_use]
    pub fn is_unconfigured(&self) -> bool {
        self.collections
            .values()
            .all(|collection| collection.mode != Mode::Enabled && collection.rules.is_empty())
    }

    /// The mode of the executable collection as this policy, an earlier-state record, holds it
    /// where the collection has no rule and a mode other than not configured: the state that a
    /// computer can be in before the installation and that the removal writes back as it was.
    #[must_use]
    pub fn recorded_empty_mode(&self) -> Option<Mode> {
        self.collections
            .get(EXE)
            .filter(|collection| {
                collection.rules.is_empty() && collection.mode != Mode::NotConfigured
            })
            .map(|collection| collection.mode)
    }

    /// The mode of the executable collection, where the policy holds one.
    #[must_use]
    pub fn exe_mode(&self) -> Option<Mode> {
        self.collections.get(EXE).map(|collection| collection.mode)
    }

    /// Whether the executable collection holds a rule that is this installation's own.
    #[must_use]
    pub fn holds_our_rules(&self) -> bool {
        let ours = [RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT];
        self.collections.get(EXE).is_some_and(|collection| {
            collection
                .rules
                .keys()
                .any(|id| ours.contains(&id.as_str()))
        })
    }

    /// The rules of the executable collection that are not this installation's own.
    #[must_use]
    pub fn foreign_exe_rules(&self) -> Vec<&Rule> {
        let ours = [RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT];
        self.collections
            .get(EXE)
            .map_or_else(Vec::new, |collection| {
                collection
                    .rules
                    .values()
                    .filter(|rule| !ours.contains(&rule.id.as_str()))
                    .collect()
            })
    }

    /// The policy that holds once this installation's rules are removed, and whether the allow-all
    /// rule had to stay.
    ///
    /// When nothing else is left in the executable collection every rule of ours goes and the
    /// collection returns to not configured. When another rule shares the collection, the two deny
    /// rules go and the allow-all rule and the collection's mode stay: taking the allow-all rule
    /// away would turn the other rule into a block for every account it does not name.
    #[must_use]
    pub fn without_ours(&self) -> (Policy, bool) {
        let mut policy = self.clone();
        let mut kept_allow_all = false;
        if let Some(collection) = policy.collections.get_mut(EXE) {
            collection.rules.remove(RULE_CHECKOUT);
            collection.rules.remove(RULE_CONNECT);
            let others = collection.rules.keys().any(|id| id != RULE_ALLOW_ALL);
            if others {
                kept_allow_all = collection.rules.contains_key(RULE_ALLOW_ALL);
            } else {
                collection.rules.remove(RULE_ALLOW_ALL);
                collection.mode = Mode::NotConfigured;
            }
        }
        (policy, kept_allow_all)
    }

    /// Names what differs between this policy and the one expected, one line for each difference.
    /// An empty answer means they are equal.
    #[must_use]
    pub fn differences(&self, expected: &Policy) -> Vec<String> {
        let mut lines = Vec::new();
        let names: BTreeSet<&String> = self
            .collections
            .keys()
            .chain(expected.collections.keys())
            .collect();
        let none = Collection {
            mode: Mode::NotConfigured,
            rules: BTreeMap::new(),
        };
        for name in names {
            let have = self.collections.get(name).unwrap_or(&none);
            let want = expected.collections.get(name).unwrap_or(&none);
            if have.mode != want.mode {
                lines.push(format!(
                    "the {name} collection is {:?}, not {:?}",
                    have.mode, want.mode
                ));
            }
            let ids: BTreeSet<&String> = have.rules.keys().chain(want.rules.keys()).collect();
            for id in ids {
                match (have.rules.get(id), want.rules.get(id)) {
                    (Some(_), None) => {
                        lines.push(format!(
                            "the {name} collection has the rule {id}, which the expected policy does not have"
                        ));
                    }
                    (None, Some(_)) => lines.push(format!("the {name} rule {id} is missing")),
                    (Some(a), Some(b)) if a != b => {
                        let mut parts = Vec::new();
                        if a.kind != b.kind {
                            parts.push("kind");
                        }
                        if a.sid != b.sid {
                            parts.push("account");
                        }
                        if a.action != b.action {
                            parts.push("action");
                        }
                        if a.conditions != b.conditions {
                            parts.push("conditions");
                        }
                        if a.exceptions != b.exceptions {
                            parts.push("exceptions");
                        }
                        lines.push(format!(
                            "the {name} rule {id} changed: {}",
                            parts.join(", ")
                        ));
                    }
                    _ => {}
                }
            }
        }
        lines
    }

    /// Writes the policy as the XML the platform's own tool applies. Only path rules are written.
    #[must_use]
    pub fn render(&self) -> String {
        let mut xml = String::from("<AppLockerPolicy Version=\"1\">\n");
        for (name, collection) in &self.collections {
            let mode = match collection.mode {
                Mode::NotConfigured => "NotConfigured",
                Mode::AuditOnly => "AuditOnly",
                Mode::Enabled => "Enabled",
            };
            let _ = writeln!(
                xml,
                "  <RuleCollection Type=\"{}\" EnforcementMode=\"{mode}\">",
                escape(name)
            );
            for rule in collection.rules.values() {
                let action = match rule.action {
                    Action::Allow => "Allow",
                    Action::Deny => "Deny",
                };
                let _ = writeln!(
                    xml,
                    "    <FilePathRule Id=\"{}\" Name=\"{}\" Description=\"{}\" UserOrGroupSid=\"{}\" Action=\"{action}\">",
                    escape(&rule.id),
                    escape(rule_name(&rule.id)),
                    escape(rule_description(&rule.id)),
                    escape(&rule.sid)
                );
                xml.push_str("      <Conditions>\n");
                for path in &rule.conditions {
                    let _ = writeln!(
                        xml,
                        "        <FilePathCondition Path=\"{}\" />",
                        escape(path)
                    );
                }
                xml.push_str("      </Conditions>\n");
                if !rule.exceptions.is_empty() {
                    xml.push_str("      <Exceptions>\n");
                    for path in &rule.exceptions {
                        let _ = writeln!(
                            xml,
                            "        <FilePathCondition Path=\"{}\" />",
                            escape(path)
                        );
                    }
                    xml.push_str("      </Exceptions>\n");
                }
                xml.push_str("    </FilePathRule>\n");
            }
            xml.push_str("  </RuleCollection>\n");
        }
        xml.push_str("</AppLockerPolicy>\n");
        xml
    }

    /// Reads the XML the platform reports as the effective policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Unreadable`] when the text is not well-formed or is not a policy.
    pub fn parse(xml: &str) -> Result<Policy, PolicyError> {
        let mut reader = Reader::from_str(xml);
        let mut policy = Policy::default();
        let mut collection: Option<(String, Collection)> = None;
        let mut rule: Option<Rule> = None;
        let mut in_exceptions = false;
        let mut seen_root = false;
        loop {
            let event = reader
                .read_event()
                .map_err(|error| PolicyError::Unreadable(error.to_string()))?;
            match event {
                Event::Start(element) => {
                    open(
                        &element,
                        &mut seen_root,
                        &mut collection,
                        &mut rule,
                        &mut in_exceptions,
                    )?;
                }
                Event::Empty(element) => {
                    open(
                        &element,
                        &mut seen_root,
                        &mut collection,
                        &mut rule,
                        &mut in_exceptions,
                    )?;
                    let name = element.local_name().as_ref().to_owned();
                    close(
                        &name,
                        &mut policy,
                        &mut collection,
                        &mut rule,
                        &mut in_exceptions,
                    );
                }
                Event::End(element) => {
                    let name = element.local_name().as_ref().to_owned();
                    close(
                        &name,
                        &mut policy,
                        &mut collection,
                        &mut rule,
                        &mut in_exceptions,
                    );
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !seen_root {
            return Err(PolicyError::Unreadable(
                "there is no AppLockerPolicy element".to_owned(),
            ));
        }
        Ok(policy)
    }
}

fn attribute(element: &BytesStart<'_>, name: &str) -> Result<Option<String>, PolicyError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| PolicyError::Unreadable(error.to_string()))?;
        if attribute.key.local_name().as_ref() == name {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|error| PolicyError::Unreadable(error.to_string()))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// A field that the entry must carry and must give a value to: its value, or the refusal that names
/// the entry and the field.
fn required(element: &BytesStart<'_>, field: &str, entry: &str) -> Result<String, PolicyError> {
    let value = attribute(element, field)?
        .ok_or_else(|| PolicyError::Unknown(format!("{entry} has no {field}")))?;
    if value.trim().is_empty() {
        return Err(PolicyError::Unknown(format!(
            "{entry} has an empty {field}"
        )));
    }
    Ok(value)
}

/// A value that no known form matches: the refusal names the entry, the field and the value.
fn not_known(entry: &str, field: &str, value: &str) -> PolicyError {
    let shown = if value.chars().count() > 60 {
        format!("{}...", value.chars().take(60).collect::<String>())
    } else {
        value.to_owned()
    };
    PolicyError::Unknown(format!(
        "{entry} has the {field} \"{shown}\", which this program does not know"
    ))
}

fn open(
    element: &BytesStart<'_>,
    seen_root: &mut bool,
    collection: &mut Option<(String, Collection)>,
    rule: &mut Option<Rule>,
    in_exceptions: &mut bool,
) -> Result<(), PolicyError> {
    let name = element.local_name().as_ref().to_owned();
    match name.as_str() {
        "AppLockerPolicy" => *seen_root = true,
        "RuleCollection" => {
            let kind = required(element, "Type", "a RuleCollection")?;
            let entry = format!("the {kind} RuleCollection");
            let mode = match required(element, "EnforcementMode", &entry)?.as_str() {
                "Enabled" => Mode::Enabled,
                "AuditOnly" => Mode::AuditOnly,
                "NotConfigured" => Mode::NotConfigured,
                other => return Err(not_known(&entry, "EnforcementMode", other)),
            };
            *collection = Some((
                kind,
                Collection {
                    mode,
                    rules: BTreeMap::new(),
                },
            ));
        }
        "FilePathRule" | "FilePublisherRule" | "FileHashRule" => {
            let kind = match name.as_str() {
                "FilePathRule" => Kind::Path,
                "FilePublisherRule" => Kind::Publisher,
                _ => Kind::Hash,
            };
            let entry = format!("a {name}");
            let action = match required(element, "Action", &entry)?.as_str() {
                "Allow" => Action::Allow,
                "Deny" => Action::Deny,
                other => return Err(not_known(&entry, "Action", other)),
            };
            let given = required(element, "Id", &entry)?;
            let id = normal_id(&given);
            if !is_rule_id(&id) {
                return Err(not_known(&entry, "Id", &given));
            }
            let given = required(element, "UserOrGroupSid", &entry)?;
            let sid = given.trim().to_uppercase();
            if !is_account_id(&sid) {
                return Err(not_known(&entry, "UserOrGroupSid", &given));
            }
            *rule = Some(Rule {
                id,
                kind,
                sid,
                action,
                conditions: BTreeSet::new(),
                exceptions: BTreeSet::new(),
            });
        }
        "Exceptions" => *in_exceptions = true,
        "FilePathCondition" => {
            if let Some(rule) = rule.as_mut() {
                let path = normal_path(&required(element, "Path", "a FilePathCondition")?);
                if *in_exceptions {
                    rule.exceptions.insert(path);
                } else {
                    rule.conditions.insert(path);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn close(
    name: &str,
    policy: &mut Policy,
    collection: &mut Option<(String, Collection)>,
    rule: &mut Option<Rule>,
    in_exceptions: &mut bool,
) {
    match name {
        "Exceptions" => *in_exceptions = false,
        "FilePathRule" | "FilePublisherRule" | "FileHashRule" => {
            if let (Some(rule), Some((_, collection))) = (rule.take(), collection.as_mut()) {
                collection.rules.insert(rule.id.clone(), rule);
            }
        }
        "RuleCollection" => {
            if let Some((kind, collection)) = collection.take() {
                policy.collections.insert(kind, collection);
            }
        }
        _ => {}
    }
}

/// What [`strip`] writes for an executable collection that is left with no rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emptied {
    /// The collection goes back to not configured.
    NotConfigured,
    /// The collection is written with this mode, as an earlier-state record holds an empty
    /// collection of that mode.
    Mode(Mode),
    /// The collection's own element is left as the platform wrote it, mode and all.
    AsFound,
}

/// Takes the rules with the given identifiers out of a policy's own XML and leaves everything
/// else exactly as the platform wrote it: another rule's name, its kind and its conditions, and the
/// collections this crate does not model. An executable collection left with no rule is written as
/// `emptied` says.
///
/// # Errors
///
/// Returns [`PolicyError::Unreadable`] when the text is not a policy.
pub fn strip(xml: &str, drop: &[&str], emptied: Emptied) -> Result<String, PolicyError> {
    let unreadable = |error: &dyn std::fmt::Display| PolicyError::Unreadable(error.to_string());
    let policy = Policy::parse(xml)?;
    let exe_left = policy.collections.get(EXE).map_or(0, |collection| {
        collection
            .rules
            .keys()
            .filter(|id| !drop.contains(&id.as_str()))
            .count()
    });
    let rewrite = emptied != Emptied::AsFound;
    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::new());
    let mut skipping = 0_usize;
    loop {
        let event = reader.read_event().map_err(|error| unreadable(&error))?;
        if skipping > 0 {
            match event {
                Event::Start(_) => skipping += 1,
                Event::End(_) => skipping -= 1,
                Event::Eof => {
                    return Err(PolicyError::Unreadable(
                        "the policy ends inside a rule".to_owned(),
                    ));
                }
                _ => {}
            }
            continue;
        }
        match event {
            Event::Eof => break,
            Event::Start(element) if dropped(&element, drop)? => skipping = 1,
            Event::Empty(element) if dropped(&element, drop)? => {}
            Event::Start(element) if rewrite && exe_is_empty(&element, exe_left)? => writer
                .write_event(Event::Start(emptied_collection(emptied)))
                .map_err(|error| unreadable(&error))?,
            Event::Empty(element) if rewrite && exe_is_empty(&element, exe_left)? => writer
                .write_event(Event::Empty(emptied_collection(emptied)))
                .map_err(|error| unreadable(&error))?,
            other => writer
                .write_event(other)
                .map_err(|error| unreadable(&error))?,
        }
    }
    String::from_utf8(writer.into_inner()).map_err(|error| unreadable(&error))
}

fn dropped(element: &BytesStart<'_>, drop: &[&str]) -> Result<bool, PolicyError> {
    let name = element.local_name().as_ref().to_owned();
    if !matches!(
        name.as_str(),
        "FilePathRule" | "FilePublisherRule" | "FileHashRule"
    ) {
        return Ok(false);
    }
    let id = normal_id(&attribute(element, "Id")?.unwrap_or_default());
    Ok(drop.contains(&id.as_str()))
}

fn exe_is_empty(element: &BytesStart<'_>, exe_left: usize) -> Result<bool, PolicyError> {
    Ok(exe_left == 0
        && element.local_name().as_ref() == "RuleCollection"
        && attribute(element, "Type")?.as_deref() == Some(EXE))
}

/// The element of an executable collection that [`strip`] left with no rule, with its type and its
/// mode and nothing else.
fn emptied_collection(emptied: Emptied) -> BytesStart<'static> {
    let mode = match emptied {
        Emptied::Mode(Mode::AuditOnly) => "AuditOnly",
        Emptied::Mode(Mode::Enabled) => "Enabled",
        Emptied::NotConfigured | Emptied::Mode(Mode::NotConfigured) | Emptied::AsFound => {
            "NotConfigured"
        }
    };
    let mut element = BytesStart::new("RuleCollection");
    element.push_attribute(("Type", EXE));
    element.push_attribute(("EnforcementMode", mode));
    element
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn rule_name(id: &str) -> &'static str {
    match id {
        RULE_ALLOW_ALL => "KalaReach: every account may run every program",
        RULE_CHECKOUT => "KalaReach: the checkout account runs only Git",
        RULE_CONNECT => {
            "KalaReach: the connection account runs only Git, its transport programs and the credential helper"
        }
        _ => "Rule added by an administrator",
    }
}

fn rule_description(id: &str) -> &'static str {
    match id {
        RULE_ALLOW_ALL => {
            "Keeps every account unrestricted except the two repository boundary accounts."
        }
        RULE_CHECKOUT => "Denies every program except Git's own git.exe.",
        RULE_CONNECT => {
            "Denies every program except the listed programs of Git's installation and the credential helper."
        }
        _ => "Added by an administrator.",
    }
}
