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
//! level that is not excluded, taken from the complete list of `packages/v*` tags on origin and not
//! from the history of the commit, and fails naming the release and each difference:
//!
//! * the schema, cut over the roots of the retained surface (`SURFACE_ROOTS`) and the types the
//!   peers of a worker exchange with it directly (`worker_surface::peer_roots`), with both
//!   revisions' root lists, so a root one of them dropped cannot hide a difference;
//! * the methods a worker serves and the notifications it sends, with the types they carry, from
//!   the `worker-surface.json` each release committed: a renamed event or a method no longer
//!   served changes no definition. A release before that file is compared by schema alone, and
//!   the run says so;
//! * the protocol the plugin host speaks and the table of public majors.
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

use crate::excluded::{Exclusions, kept};
use crate::releases::{
    Release, agree_with_origin, file_at, git_in, inventory, package_version_at, surface_roots_at,
};
use crate::retained::{expected_public_majors_in, plugin_host_in};

/// Where a release keeps the table of what its worker serves, from the root of the repository.
pub const WORKER_SURFACE_PATH: &str = "crates/kr-protocol/worker-surface.json";

/// Where a release keeps its generated schema.
pub const SCHEMA_PATH: &str = "packages/protocol/schema/kalareach-protocol.schema.json";

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
            methods.insert(
                field(item, "name")?,
                (field(item, "params")?, field(item, "result")?),
            );
        }
        let mut events = BTreeMap::new();
        for item in document
            .get("events")
            .and_then(Value::as_array)
            .ok_or("no events")?
        {
            events.insert(field(item, "name")?, field(item, "payload")?);
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
    /// What it serves.
    pub worker: WorkerSurface,
    /// The protocol its plugin host speaks.
    pub plugin_host: String,
    /// The record of its table of public majors.
    pub public_majors: String,
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
        Ok(Self {
            commit: commit.to_owned(),
            level: CompatibilityLevel::of(PACKAGE_VERSION),
            schema: kr_protocol::schema::protocol_schema(),
            worker: WorkerSurface::parse(&worker_surface::document())?,
            plugin_host: PLUGIN_HOST_PROTOCOL.to_owned(),
            public_majors: expected_public_majors_in(repository, commit)?,
        })
    }
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

/// Compares `head` with every release at its level that is not excluded.
///
/// # Errors
///
/// What differs, release by release; or what could not be read.
pub fn check(
    repository: &Path,
    head: &Head,
    inventory: &[Release],
    exclusions: &Exclusions,
) -> Result<Outcome, String> {
    let at_level = inventory
        .iter()
        .filter(|release| release.level() == head.level && release.commit != head.commit);
    if at_level.count() == 0 {
        return Ok(Outcome::MovesTheLevel);
    }
    let peers = kept(inventory, head.level, exclusions, &head.commit);
    if peers.is_empty() {
        // The record refuses a level none of whose releases is kept, so the commit's own tag is the
        // level's only kept release: nothing else says what the level is.
        return Ok(Outcome::Held {
            releases: Vec::new(),
            notes: vec![format!(
                "this commit is the only release of level {} that is not excluded",
                head.level
            )],
        });
    }
    let mut problems = Vec::new();
    let mut notes = Vec::new();
    for release in &peers {
        let stated = package_version_at(repository, &release.commit)?;
        if stated != release.version {
            return Err(format!(
                "{} states {} and its commit's package is {stated}",
                release.tag, release.version
            ));
        }
        let found = compare(repository, head, release, &mut notes)?;
        if !found.is_empty() {
            problems.push(format!(
                "{} speaks another surface than this commit at level {}:\n  {}",
                release.tag,
                head.level,
                found.join("\n  ")
            ));
        }
    }
    if problems.is_empty() {
        return Ok(Outcome::Held {
            releases: peers.into_iter().map(|release| release.tag).collect(),
            notes,
        });
    }
    Err(format!(
        "{}\na level is one surface: a change to it after the level's first release moves the level \
         in the train that makes it, with its cut (docs/releases/support-window.md)",
        problems.join("\n")
    ))
}

/// What differs between one release and the head: each as a line.
fn compare(
    repository: &Path,
    head: &Head,
    release: &Release,
    notes: &mut Vec<String>,
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
             compared, its schema is"
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
/// listed and held to this checkout's, the record of exclusions is read and held to them, and the
/// commit is compared, or when it moves the level the cut's own check is run (`cut`).
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
    let exclusions = Exclusions::read(repository)?;
    exclusions.validate(repository, &release_tags)?;
    let head = Head::of_this_build(repository, &commit)?;
    conclude(
        repository,
        &head,
        &release_tags,
        &exclusions,
        cut,
        &run_cut_check,
    )
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
    exclusions: &Exclusions,
    cut: bool,
    cut_check: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let commit = &head.commit;
    match check(repository, head, release_tags, exclusions)? {
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
