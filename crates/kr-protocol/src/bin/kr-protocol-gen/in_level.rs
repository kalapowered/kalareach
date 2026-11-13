//! The in-level check: a level is one surface.
//!
//! ```text
//! kr-protocol-gen --in-level
//! ```
//!
//! Every release at a level reads and writes the frames of that level, so a build at the level
//! meets workers of any of them, across an update and a rollback. The first release of a level
//! therefore fixes what the level is, and a change to it after that moves the level, in the train
//! that makes it, with its cut. This compares the commit being released with every release at its
//! level, taken from the complete list of `packages/v*` tags on origin and not from the history of
//! the commit, and fails naming the release and each difference:
//!
//! * the schema, cut over the roots of the retained surface (`SURFACE_ROOTS`) and the types the
//!   peers of a worker exchange with it directly (`worker_surface::peer_roots`), with both
//!   revisions' root lists, so a root one of them dropped cannot hide a difference;
//! * the methods a worker serves and the notifications it sends, with the types they carry, from
//!   the `worker-surface.json` each release committed: a renamed event or a method no longer
//!   served changes no definition. A release before that file has no tables to compare, so they
//!   are left out for it and the run says so;
//! * the protocol the plugin host speaks and the table of public majors;
//! * the whole protocol schema, every definition a root, which is what a client built from the
//!   protocol package reads: a member or a variant added to an existing definition, and anything
//!   removed or changed, is a difference. A definition that is new, a new method and an optional
//!   member added to an object the earlier release marked read-only metadata are not, nor is a new
//!   section of the host configuration document, a stored file read by level, which the build
//!   lists above the level the earlier release's stored-format lock records (the run says each
//!   section it passes, because the comparison cannot tell a section from a restriction). A new
//!   method is a name that this commit's `Method` adds to the earlier release's, where both are a
//!   list of plain string constants and nothing else, each name stands once in the shape of a
//!   method's name (lower-case words of letters, digits and underscores, with single dots
//!   between), the earlier release's names are all still there, and every use of `Method` in the
//!   schema is one that a wider `Method` only widens (a property, an item, an `anyOf`, an `allOf`;
//!   not a `oneOf`, a `not` or an `if`) (a host of the same level answers
//!   a method it does not list with `PERMISSION_DENIED`, and a client that meets that refusal for
//!   a method that is new asks the host a method its level has before it takes the refusal for a
//!   lack of rights);
//! * the plugin SDK schema, from the committed file of each release and of this commit, held to
//!   the same rule for what fails, and to a narrower one for what passes. The files are
//!   generated, and `kr-plugin-sdk-gen --check` holds the committed ones equal to the generated
//!   ones. A release of the level without the schema or without `package-contract.json`, or a
//!   file that does not read, fails the check. Only a definition that is new passes, and one kind
//!   of member: an optional member of a definition that is a plain closed object in both schemas
//!   (`type` is `object`, `additionalProperties` is `false`, and its own keys are among `type`,
//!   `properties`, `required`, `additionalProperties`, `description` and `title`), that no
//!   protocol schema has, and that the connector table's root reaches and the package manifest's
//!   root does not, which this commit's arrival table (in its `package-contract.json`) lists at
//!   an SDK version above the release's own `sdk_version`, in a commit whose SDK version is above
//!   that version too (`compare_sdk_for_a_level`). The protocol's read-only metadata marker has
//!   no meaning in the SDK's schema, so an unlisted member of an SDK definition that carries it
//!   fails like any other. The table lists a member only where a
//!   package that lacks it means what it meant before, and a host of an earlier SDK refuses a
//!   package that uses it, because it tests the package's `sdk_range` first; the comparison sees
//!   neither, and the review of the change that lists a member must. The run says each member it
//!   passes, with both versions. Everything else fails: a required member, a member the table
//!   does not list, one listed with no rise of the SDK version, a member of a definition the
//!   protocol schema has, a nested member, a variant, a change or a removal, a lower SDK version,
//!   and an entry of a release's table that this commit's table changes or lacks. A release from
//!   before the table has an empty one. When a member would pass and a definition of both schemas
//!   points a reference at another definition than it did, every arrival fails, because the
//!   comparison goes by where a definition is used and not by its name; this holds for a
//!   reference to an equal definition and for `oneOf` branches in a new order too.
//!
//! What it does not see: the `kr-plugin-host/3` frames, which have no schema; the types a
//! daemon-served method names only in its description; rules that live in code; the hand-written
//! TypeScript exports; the rest of `package-contract.json` (its limits and tables) and the
//! component interface. A difference it fails on that is harmless takes a cut or a reviewed
//! change of the comparison in `public_contract.rs`.
//!
//! It fails closed. It cannot list origin's tags, this checkout's tags are not origin's, a release's
//! tree cannot be read, or a source is in a form it does not read: each is a failure with its own
//! message, never a release left out. When no release is at the commit's level, the commit moves the
//! level, and the cut's own check, `scripts/check-retained-release.sh`, runs in the same run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::retained::{PLUGIN_HOST_PROTOCOL, Surface, SurfaceError};
use kr_protocol::update::CompatibilityLevel;
use kr_protocol::worker_surface;
use serde_json::Value;

use crate::public_contract::{
    PassedMember, SdkContract, compare_for_a_level, compare_sdk_for_a_level,
};
use crate::releases::{
    Release, agree_with_origin, file_at, git_in, inventory, kept, package_version_at,
    surface_roots_at,
};
use crate::retained::{expected_public_majors_in, plugin_host_in};

/// Where a release keeps the table of what its worker serves, from the root of the repository.
pub const WORKER_SURFACE_PATH: &str = "crates/kr-protocol/worker-surface.json";

/// Where a release keeps its stored-format lock, from the root of the repository.
pub const LOCK_PATH: &str = "stored-formats.lock";

/// Where a release keeps its generated schema.
pub const SCHEMA_PATH: &str = "packages/protocol/schema/kalareach-protocol.schema.json";

/// Where a release keeps the schema of the plugin SDK, from the root of the repository.
pub const SDK_SCHEMA_PATH: &str = "packages/plugin-sdk/schema/kalareach-plugin-sdk.schema.json";

/// Where a release keeps the plugin SDK's package contract, which states the SDK's version and the
/// table of members that arrived inside a level.
pub const SDK_CONTRACT_PATH: &str = "packages/plugin-sdk/schema/package-contract.json";

/// The tables of what a worker serves, as a release committed them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerSurface {
    surface_roots: Vec<String>,
    peer_roots: Vec<String>,
    /// Each served method, with the schema names of its parameters and its result.
    methods: BTreeMap<String, (String, String)>,
    /// Each notification, with the schema name of its payload.
    events: BTreeMap<String, String>,
}

impl WorkerSurface {
    /// Reads the document `kr_protocol::worker_surface::document` writes.
    ///
    /// # Errors
    ///
    /// When it is not that document.
    pub fn parse(text: &str) -> Result<Self, String> {
        let document: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
        let texts = |name: &str| -> Result<Vec<String>, String> {
            document
                .get(name)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("no {name}"))?
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("{name} holds something that is not text"))
                })
                .collect()
        };
        let field = |item: &Value, name: &str| -> Result<String, String> {
            item.get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("a row has no {name}"))
        };
        let mut methods = BTreeMap::new();
        for item in document
            .get("methods")
            .and_then(Value::as_array)
            .ok_or("no methods")?
        {
            let name = field(item, "name")?;
            if methods
                .insert(
                    name.clone(),
                    (field(item, "params")?, field(item, "result")?),
                )
                .is_some()
            {
                return Err(format!("the table lists the method {name} twice"));
            }
        }
        let mut events = BTreeMap::new();
        for item in document
            .get("events")
            .and_then(Value::as_array)
            .ok_or("no events")?
        {
            let name = field(item, "name")?;
            if events
                .insert(name.clone(), field(item, "payload")?)
                .is_some()
            {
                return Err(format!("the table lists the event {name} twice"));
            }
        }
        Ok(Self {
            surface_roots: texts("surface_roots")?,
            peer_roots: texts("peer_roots")?,
            methods,
            events,
        })
    }
}

/// The commit being checked, as this build has it.
pub struct Head {
    /// The full commit.
    pub commit: String,
    /// The level it is at.
    pub level: CompatibilityLevel,
    /// Its generated schema.
    pub schema: Value,
    /// The plugin SDK schema it committed.
    pub sdk_schema: Value,
    /// The SDK version and the table of arrivals its package contract states.
    pub sdk_contract: SdkContract,
    /// What it serves.
    pub worker: WorkerSurface,
    /// The protocol its plugin host speaks.
    pub plugin_host: String,
    /// The record of its table of public majors.
    pub public_majors: String,
    /// The sections of the host configuration document that arrived with a level, each with the
    /// level, as the build lists them.
    pub sections: Vec<(String, u64)>,
}

impl Head {
    /// This build, which has to be the one `commit` makes.
    ///
    /// # Errors
    ///
    /// When the package at `commit` is not this build's, or its table of public majors cannot be
    /// read.
    pub fn of_this_build(repository: &Path, commit: &str) -> Result<Self, String> {
        let stated = package_version_at(repository, commit)?;
        if stated != PACKAGE_VERSION {
            return Err(format!(
                "the package at {commit} is {stated} and this build is {PACKAGE_VERSION}; run this \
                 in a clean checkout of the commit to release"
            ));
        }
        let sdk_schema = file_at(repository, commit, SDK_SCHEMA_PATH)
            .map_err(|error| format!("{SDK_SCHEMA_PATH} at {commit} cannot be read: {error}"))?
            .ok_or_else(|| format!("{commit} has no {SDK_SCHEMA_PATH}"))
            .and_then(|text| {
                serde_json::from_str(&text)
                    .map_err(|error| format!("{SDK_SCHEMA_PATH} at {commit}: {error}"))
            })?;
        let sdk_contract = file_at(repository, commit, SDK_CONTRACT_PATH)
            .map_err(|error| format!("{SDK_CONTRACT_PATH} at {commit} cannot be read: {error}"))?
            .ok_or_else(|| format!("{commit} has no {SDK_CONTRACT_PATH}"))
            .and_then(|text| {
                SdkContract::parse(&text)
                    .map_err(|error| format!("{SDK_CONTRACT_PATH} at {commit}: {error}"))
            })?;
        Ok(Self {
            commit: commit.to_owned(),
            level: CompatibilityLevel::of(PACKAGE_VERSION),
            schema: kr_protocol::schema::protocol_schema(),
            sdk_schema,
            sdk_contract,
            worker: WorkerSurface::parse(&worker_surface::document())?,
            plugin_host: PLUGIN_HOST_PROTOCOL.to_owned(),
            public_majors: expected_public_majors_in(repository, commit)?,
            sections: kr_protocol::hostinfo::configuration::LEVELLED
                .iter()
                .map(|section| (section.member.to_owned(), section.level))
                .collect(),
        })
    }
}

/// The level of the configuration document that a release's stored-format lock records: the
/// highest level of the sections that release reads.
///
/// # Errors
///
/// When the release has no lock, the lock does not read, lists no configuration document, or
/// records no level or one that is no whole number: each is a failure and never a guess. (A release
/// of the level that records no level reads no sections, and the member `level` that the document
/// gained with levels would be the first difference.)
pub fn configuration_level_at(repository: &Path, commit: &str) -> Result<u64, String> {
    let text = file_at(repository, commit, LOCK_PATH)
        .map_err(|error| format!("{LOCK_PATH} at {commit} cannot be read: {error}"))?
        .ok_or_else(|| {
            format!(
                "{commit} has no {LOCK_PATH}, so the level of its configuration document is not \
                 known"
            )
        })?;
    let lock: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{LOCK_PATH} at {commit} does not read: {error}"))?;
    let document = lock
        .get("stores")
        .and_then(Value::as_array)
        .and_then(|stores| {
            stores
                .iter()
                .find(|store| store["entry"]["store"].as_str() == Some("configuration"))
        })
        .ok_or_else(|| format!("{LOCK_PATH} at {commit} lists no configuration document"))?;
    document
        .get("level")
        .and_then(Value::as_u64)
        .filter(|level| *level >= 1)
        .ok_or_else(|| {
            format!(
                "{LOCK_PATH} at {commit} records no level of the configuration document, or one \
                 that is not a whole number of at least 1"
            )
        })
}

/// What the check found when it did not fail.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No release is at the commit's level: the commit moves it.
    MovesTheLevel,
    /// Every kept release at the level has the commit's surface.
    Held {
        /// The releases compared.
        releases: Vec<String>,
        /// What was not compared, and why.
        notes: Vec<String>,
    },
}

/// Cuts the surface of `roots` out of `schema`, leaving out a root the schema does not define: the
/// difference between two surfaces cut this way names such a root as one that is missing.
///
/// # Errors
///
/// When the schema is not a bundle of definitions, or a definition refers to one it lacks.
pub fn cut_over(schema: &Value, roots: &BTreeSet<String>) -> Result<Surface, SurfaceError> {
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .ok_or_else(|| SurfaceError::NotASurface("no $defs".to_owned()))?;
    let defined: Vec<&str> = roots
        .iter()
        .filter(|root| definitions.contains_key(root.as_str()))
        .map(String::as_str)
        .collect();
    Surface::cut(schema, &defined)
}

/// Fails unless every root a revision declares is a definition of that revision's own schema: a
/// root that is not is a misspelling or a stale list, and cutting over it would hide it.
///
/// # Errors
///
/// Naming each root that is missing, and whose declaration it is.
pub fn declared_in(schema: &Value, roots: &BTreeSet<String>, whose: &str) -> Result<(), String> {
    let missing: Vec<&str> = roots
        .iter()
        .filter(|root| schema["$defs"].get(root.as_str()).is_none())
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{whose} declares the roots {} and its schema has no definition of them",
            missing.join(", ")
        ))
    }
}

/// Compares `head` with every release at its level.
///
/// # Errors
///
/// What differs, release by release; or what could not be read.
pub fn check(repository: &Path, head: &Head, inventory: &[Release]) -> Result<Outcome, String> {
    let at_level = inventory
        .iter()
        .filter(|release| release.level() == head.level && release.commit != head.commit);
    if at_level.count() == 0 {
        return Ok(Outcome::MovesTheLevel);
    }
    let peers = kept(inventory, head.level, &head.commit);
    if peers.is_empty() {
        // The commit's own tag is the level's only release: nothing else says what the level is.
        return Ok(Outcome::Held {
            releases: Vec::new(),
            notes: vec![format!(
                "this commit is the only release of level {}",
                head.level
            )],
        });
    }
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    // Each section of the configuration document that passed, with the releases it is new to.
    let mut sections: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Each member of the plugin SDK's schema that passed because the SDK lists it, with the release
    // it is new to.
    let mut arrivals: Vec<(String, PassedMember)> = Vec::new();
    // A release that cannot be read stops the run, and the members that passed against the
    // releases before it are said with its error.
    let mut unread: Option<String> = None;
    for release in &peers {
        let mut step = || -> Result<(), String> {
            let stated = package_version_at(repository, &release.commit)?;
            if stated != release.version {
                return Err(format!(
                    "{} states {} and its commit's package is {stated}",
                    release.tag, release.version
                ));
            }
            let found = compare(
                repository,
                head,
                release,
                &mut notes,
                &mut sections,
                &mut arrivals,
            )?;
            if !found.is_empty() {
                problems.push(format!(
                    "{} speaks another surface than this commit at level {}:\n  {}",
                    release.tag,
                    head.level,
                    found.join("\n  ")
                ));
            }
            Ok(())
        };
        if let Err(error) = step() {
            unread = Some(error);
            break;
        }
    }
    // The comparison cannot tell a member whose absence keeps the earlier meaning from one
    // whose absence does not, so each member it passes is said once, with the version it
    // arrived at and the version of the releases it is new to, for the review of the change
    // that lists it. A run that fails says them too, so that one run shows the whole state.
    let mut grouped: BTreeMap<(String, String, String), Vec<String>> = BTreeMap::new();
    let mut arrival_notes: Vec<String> = Vec::new();
    for (tag, passed) in arrivals {
        grouped
            .entry((
                passed.member,
                passed.arrived.to_string(),
                passed.earlier.to_string(),
            ))
            .or_default()
            .push(tag);
    }
    for ((member, arrived, earlier), tags) in grouped {
        arrival_notes.push(format!(
            "the plugin SDK member {member}, listed in the arrival table at SDK {arrived}, is \
             new to {} (SDK {earlier}) and passes as an optional member of a definition that \
             no protocol schema has, the connector table reaches and the package manifest does \
             not; the comparison cannot tell it from a member whose absence \
             changes the meaning, and the review of the change that lists it must \
             (docs/releases/packages.md, \"A level is one surface\")",
            tags.join(", ")
        ));
    }
    if let Some(error) = unread {
        return Err(format!(
            "{error}{}",
            arrival_notes
                .iter()
                .map(|note| format!("\nnote: {note}"))
                .collect::<String>()
        ));
    }
    if problems.is_empty() {
        // The comparison cannot tell a section from a restriction filed as one, so each section it
        // passes is said once, with its level and the releases it is new to, for the review of the
        // change that adds it.
        for (section, releases) in sections {
            let level = head
                .sections
                .iter()
                .find(|(member, _)| *member == section)
                .map_or(0, |(_, level)| *level);
            notes.push(format!(
                "the section {section} of the configuration document, level {level}, is new to {} \
                 and passes as a section an earlier release ignores and counts; the comparison \
                 cannot tell it from a restriction, and the review of the change that adds it must \
                 (docs/releases/packages.md, \"A level is one surface\")",
                releases.join(", ")
            ));
        }
        notes.extend(arrival_notes);
        return Ok(Outcome::Held {
            releases: peers.into_iter().map(|release| release.tag).collect(),
            notes,
        });
    }
    problems.extend(
        arrival_notes
            .into_iter()
            .map(|note| format!("note: {note}")),
    );
    Err(format!(
        "{}\na level is one surface and one public contract: a change to either after the level's \
         first release moves the level in the train that makes it, with its cut \
         (docs/releases/packages.md, \"A level is one surface\"); a difference that is harmless \
         takes a cut or a reviewed change of the comparison",
        problems.join("\n")
    ))
}

/// What differs between one release and the head: each as a line.
fn compare(
    repository: &Path,
    head: &Head,
    release: &Release,
    notes: &mut Vec<String>,
    sections_passed: &mut BTreeMap<String, Vec<String>>,
    arrivals_passed: &mut Vec<(String, PassedMember)>,
) -> Result<Vec<String>, String> {
    let tag = &release.tag;
    let schema_text = git_in(
        repository,
        &["show", &format!("{}:{SCHEMA_PATH}", release.commit)],
    )
    .map_err(|error| format!("the schema of {tag} cannot be read: {error}"))?;
    let schema: Value = serde_json::from_str(&schema_text)
        .map_err(|error| format!("the schema of {tag}: {error}"))?;
    let own = file_at(repository, &release.commit, WORKER_SURFACE_PATH)
        .map_err(|error| format!("{WORKER_SURFACE_PATH} of {tag} cannot be read: {error}"))?
        .map(|text| {
            WorkerSurface::parse(&text)
                .map_err(|error| format!("{WORKER_SURFACE_PATH} of {tag}: {error}"))
        })
        .transpose()?;
    // Both revisions' roots: what the build lists, and what the release listed. Each list has to
    // name definitions of its own schema; only a root the other revision lists may be missing.
    let mut roots: BTreeSet<String> = head.worker.surface_roots.iter().cloned().collect();
    roots.extend(head.worker.peer_roots.iter().cloned());
    declared_in(&head.schema, &roots, "this commit")?;
    let mut declared: BTreeSet<String> = BTreeSet::new();
    match &own {
        Some(worker) => {
            declared.extend(worker.surface_roots.iter().cloned());
            declared.extend(worker.peer_roots.iter().cloned());
        }
        None => {
            if let Some(list) = surface_roots_at(repository, &release.commit)? {
                declared.extend(list);
            }
        }
    }
    declared_in(&schema, &declared, tag)?;
    roots.extend(declared);
    let old = cut_over(&schema, &roots).map_err(|error| format!("the schema of {tag}: {error}"))?;
    let new =
        cut_over(&head.schema, &roots).map_err(|error| format!("this commit's schema: {error}"))?;
    let mut found: Vec<String> = kr_protocol::retained::differences(&old, &new)
        .iter()
        .map(ToString::to_string)
        .collect();
    // The whole schema, which a client of the protocol package reads, and the plugin SDK schema.
    // A difference both comparisons report is one line.
    // A section of the configuration document is new to an older release when the build lists it
    // above the level that release's lock records. The lock is read only when the schemas differ by
    // a member added to the document.
    let sections = || -> Result<BTreeSet<String>, String> {
        let level = configuration_level_at(repository, &release.commit)?;
        Ok(head
            .sections
            .iter()
            .filter(|(_, arrived)| *arrived > level)
            .map(|(member, _)| member.clone())
            .collect())
    };
    let mut passed = Vec::new();
    for line in compare_for_a_level(&schema, &head.schema, &sections, &mut passed)
        .map_err(|error| format!("the schema of {tag}: {error}"))?
    {
        if !found.contains(&line) {
            found.push(line);
        }
    }
    for section in passed {
        sections_passed
            .entry(section)
            .or_default()
            .push(tag.clone());
    }
    let sdk_text = file_at(repository, &release.commit, SDK_SCHEMA_PATH)
        .map_err(|error| format!("{SDK_SCHEMA_PATH} of {tag} cannot be read: {error}"))?
        .ok_or_else(|| {
            format!("{tag} has no {SDK_SCHEMA_PATH}, so the plugin SDK schema cannot be compared with it")
        })?;
    let sdk: Value = serde_json::from_str(&sdk_text)
        .map_err(|error| format!("{SDK_SCHEMA_PATH} of {tag}: {error}"))?;
    let contract_text = file_at(repository, &release.commit, SDK_CONTRACT_PATH)
        .map_err(|error| format!("{SDK_CONTRACT_PATH} of {tag} cannot be read: {error}"))?
        .ok_or_else(|| {
            format!(
                "{tag} has no {SDK_CONTRACT_PATH}, so the plugin SDK's version and table of \
                 arrivals cannot be compared with it"
            )
        })?;
    let earlier = SdkContract::parse(&contract_text)
        .map_err(|error| format!("{SDK_CONTRACT_PATH} of {tag}: {error}"))?;
    let mut passed = Vec::new();
    found.extend(
        compare_sdk_for_a_level(
            &sdk,
            &head.sdk_schema,
            (&schema, &head.schema),
            &earlier,
            &head.sdk_contract,
            &mut passed,
        )
        .map_err(|error| format!("the plugin SDK schema of {tag}: {error}"))?
        .into_iter()
        .map(|line| format!("the plugin SDK schema: {line}")),
    );
    arrivals_passed.extend(passed.into_iter().map(|member| (tag.clone(), member)));
    let host = plugin_host_in(repository, &release.commit)?;
    if host != head.plugin_host {
        found.push(format!(
            "the plugin host protocol is {host} there and {} here",
            head.plugin_host
        ));
    }
    let majors = expected_public_majors_in(repository, &release.commit)?;
    if majors != head.public_majors {
        found.push("the table of public majors is not the same".to_owned());
    }
    match own {
        Some(worker) => found.extend(table_differences(&worker, &head.worker)),
        None => notes.push(format!(
            "{tag} has no {WORKER_SURFACE_PATH}: its served methods and notifications are not \
             compared; its schema, plugin host protocol and table of public majors are"
        )),
    }
    Ok(found)
}

/// What differs between two releases' tables of what a worker serves.
fn table_differences(old: &WorkerSurface, new: &WorkerSurface) -> Vec<String> {
    let mut found = Vec::new();
    for (name, types) in &old.methods {
        match new.methods.get(name) {
            None => found.push(format!("{name} was served there and is not served here")),
            Some(here) if here != types => found.push(format!(
                "{name} reads {} and writes {} there, and reads {} and writes {} here",
                types.0, types.1, here.0, here.1
            )),
            Some(_) => {}
        }
    }
    for name in new
        .methods
        .keys()
        .filter(|name| !old.methods.contains_key(*name))
    {
        found.push(format!("{name} is served here and was not there"));
    }
    for (name, payload) in &old.events {
        match new.events.get(name) {
            None => found.push(format!("{name} was sent there and is not sent here")),
            Some(here) if here != payload => {
                found.push(format!("{name} carries {payload} there and {here} here"))
            }
            Some(_) => {}
        }
    }
    for name in new
        .events
        .keys()
        .filter(|name| !old.events.contains_key(*name))
    {
        found.push(format!("{name} is sent here and was not there"));
    }
    found
}

/// Runs the check for the commit at `HEAD` of the checkout at `repository`: origin's tags are
/// listed and held to this checkout's, and the commit is compared, or when it moves the level the
/// cut's own check is run (`cut`).
///
/// # Errors
///
/// Whatever the check fails on.
pub fn run(repository: &Path, cut: bool) -> Result<(), String> {
    let commit = git_in(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?
        .trim()
        .to_owned();
    let release_tags = inventory(repository)?;
    agree_with_origin(repository, &release_tags, &commit)?;
    let head = Head::of_this_build(repository, &commit)?;
    conclude(repository, &head, &release_tags, cut, &run_cut_check)
}

/// Compares `head` and prints what it found; a commit that moves the level has its cut checked by
/// `cut_check` when `cut` says so.
///
/// # Errors
///
/// Whatever the comparison or the cut's check fails on.
pub fn conclude(
    repository: &Path,
    head: &Head,
    release_tags: &[Release],
    cut: bool,
    cut_check: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let commit = &head.commit;
    match check(repository, head, release_tags)? {
        Outcome::MovesTheLevel if !cut => {
            println!(
                "no release is at level {}, so {commit} moves it; its cut is not checked in this run",
                head.level
            );
            Ok(())
        }
        Outcome::MovesTheLevel => {
            println!(
                "no release is at level {}, so {commit} moves it: running the cut's own check",
                head.level
            );
            cut_check(repository)
        }
        Outcome::Held { releases, notes } => {
            for note in &notes {
                println!("note: {note}");
            }
            if releases.is_empty() {
                println!(
                    "level {} has no other kept release to hold {commit} to",
                    head.level
                );
            } else {
                println!(
                    "level {} is one surface: {commit} has the surface of {}",
                    head.level,
                    releases.join(", ")
                );
            }
            Ok(())
        }
    }
}

fn run_cut_check(repository: &Path) -> Result<(), String> {
    let status = std::process::Command::new("bash")
        .arg("scripts/check-retained-release.sh")
        .current_dir(repository)
        .status()
        .map_err(|error| format!("scripts/check-retained-release.sh did not start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("scripts/check-retained-release.sh said {status}"))
    }
}
