//! What a switch to a release needs of the stores the host keeps.
//!
//! Every store keeps the version of the format it is in, and a release lists each store its
//! programs read with the versions of it they read ([`ReleaseStore`]). A host switches to a release,
//! forward or back, only when every store it keeps is at a version that release reads: this reads
//! each one where the target's manifest says it is, with nothing of its own to say which stores
//! there are, so a store a release adds is found by an updater of an earlier release.
//!
//! It runs once every daemon has stopped and every environment's lock is held, before anything is
//! brought forward, and changes nothing but what a daemon that ended by a signal left in a log,
//! which is taken into its file first.

use std::path::{Path, PathBuf};

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::update::{Recording, ReleaseManifest, ReleaseStore, StoreScope};

use super::Unreached;
use super::inventory::Environment;
use crate::barrier::COMMAND_WRITTEN_STORES;
use crate::error::CliError;

/// A store the target cannot read as it is, and where.
pub struct Refusal {
    store: String,
    environment: Option<EnvironmentId>,
    place: PathBuf,
    why: Why,
}

enum Why {
    /// It records a version the target does not read.
    Version {
        found: u32,
        /// What an update would bring it to before the switch, where that differs.
        brought_to: Option<u32>,
        lowest: u32,
        highest: u32,
        /// Whether the store is a database, which records a schema version.
        schema: bool,
    },
    /// Its version cannot be read.
    Unreadable(Shown),
    /// The target lists it in a way this build does not know.
    Unknown(&'static str),
}

impl Refusal {
    /// What the store is called, with the environment it is in.
    fn called(&self) -> Shown {
        let store = crate::shown::store_name(&self.store);
        match self.environment {
            Some(environment) => shown!("{} of environment {}", store, environment),
            None => store,
        }
    }

    /// What a person is told of it.
    fn said(&self, target: &ReleaseManifest) -> Shown {
        let release = crate::shown::release(&target.release);
        match &self.why {
            Why::Version {
                found,
                brought_to,
                lowest,
                highest,
                schema,
            } => {
                let recorded = if *schema { "schema version" } else { "version" };
                let brought = match brought_to {
                    Some(to) => shown!(", which this command would first bring to {}", *to),
                    None => shown!(""),
                };
                shown!(
                    "{} at {} records {} {}{}, and {} reads versions {} to {}",
                    self.called(),
                    Shown::root(&self.place),
                    recorded,
                    *found,
                    brought,
                    release,
                    *lowest,
                    *highest
                )
            }
            Why::Unreadable(reason) => shown!(
                "{} at {} cannot be read: {}",
                self.called(),
                Shown::root(&self.place),
                reason.clone()
            ),
            Why::Unknown(what) => shown!(
                "{} is listed by {} with {} this kr does not know, so what it needs of that store cannot be checked",
                self.called(),
                release,
                *what
            ),
        }
    }
}

/// The refusal of a switch to `target`, naming every store it cannot read.
#[must_use]
pub fn refusal(target: &ReleaseManifest, refusals: &[Refusal]) -> CliError {
    let said = Shown::joined(refusals.iter().map(|refusal| refusal.said(target)), "; ");
    CliError::Other(shown!(
        "the switch to {} was not made, and no store was brought forward, because it cannot read the stores as they are: {}",
        crate::shown::release(&target.release),
        said
    ))
}

/// The stores `target` lists in a way this build cannot look for: a scope or a way of recording a
/// later release names. Nothing on disk changes that, so a switch to it is refused before anything
/// is stopped.
#[must_use]
pub fn unlookable(target: &ReleaseManifest) -> Vec<Refusal> {
    target
        .stores
        .iter()
        .filter_map(|listed| {
            let what = if listed.scope == StoreScope::Unknown {
                "a scope"
            } else if listed.recording == Recording::Unknown {
                "a way of recording its version"
            } else {
                return None;
            };
            Some(Refusal {
                store: listed.store.clone(),
                environment: None,
                place: PathBuf::new(),
                why: Why::Unknown(what),
            })
        })
        .collect()
}

/// What looking at the stores found.
pub struct Checked {
    /// Each store the target cannot read as it is.
    pub refusals: Vec<Refusal>,
    /// The roots a command of this store registered that could not be looked at, which the update
    /// names and goes on without.
    pub unreached: Vec<Unreached>,
}

/// A root that only a command of this store registered: no control daemon of the store served it,
/// so the update looks at what a command writes there and does nothing else with it.
struct Registered {
    host: kr_ipc::paths::HostPaths,
    /// The environment the root's identity names, when it has one.
    environment: Option<Environment>,
}

/// Looks at every store `target` lists, where the manifest says it is, and returns each that is at
/// a version the target does not read, with those [`unlookable`] too.
///
/// `environments` are the environments whose daemons have stopped and whose locks are held.
/// `published` are the directories the daemons said they read their configuration documents in,
/// by environment: each is looked at beside the places this command's own environment gives.
/// `carries` is whether the switch brings a registry that is behind forward before the target meets
/// it, which an update does and a rollback does not. `_writers` is the writers' lock, held
/// exclusively: no command writes a stored record between this look and the switch that follows it.
///
/// The roots commands registered ([`Store::registered_roots`]) and the configuration documents
/// recorded ([`Store::recorded_documents`]) are read here, under that lock, which every command
/// holds from before it registers to after it has written: a root that did not exist when the
/// survey was made can exist now, and is looked at. In a root only a command registered the stores
/// a command writes are looked at, by name, and nothing else: a daemon's store there, of this
/// store's or another's, is not this update's to refuse a switch for.
#[must_use]
pub fn check(
    target: &ReleaseManifest,
    install: &kr_ipc::install::Store,
    environments: &[&Environment],
    published: &[(EnvironmentId, PathBuf)],
    carries: bool,
    _writers: &kr_ipc::install::ExclusiveWriters,
) -> Checked {
    let mut refusals = unlookable(target);
    let mut unreached = Vec::new();
    let registered = registered(install, environments, &mut refusals, &mut unreached);
    let documents = install.recorded_documents().unwrap_or_else(|error| {
        refusals.push(Refusal {
            store: "the configuration documents the store recorded".to_owned(),
            environment: None,
            place: install.roots(),
            why: Why::Unreadable(super::said(&error)),
        });
        Vec::new()
    });
    for listed in &target.stores {
        if listed.scope == StoreScope::Unknown || listed.recording == Recording::Unknown {
            continue;
        }
        let places = Places {
            install,
            environments,
            published,
            registered: &registered,
            documents: &documents,
        };
        for (environment, directory) in places.of(listed) {
            let mut refuse = |place: PathBuf, why: Why| {
                refusals.push(Refusal {
                    store: listed.store.clone(),
                    environment,
                    place,
                    why,
                });
            };
            match files(&directory, listed) {
                Ok(found) => {
                    for file in found {
                        if let Some(why) = look(listed, &file, carries) {
                            refuse(file, why);
                        }
                    }
                }
                Err(reason) => refuse(directory.join(&listed.path), Why::Unreadable(reason)),
            }
        }
    }
    Checked {
        refusals,
        unreached,
    }
}

/// Looks at the state root of every root a command registered, before anything is stopped, so that a
/// place that hangs when it is looked at holds the update while nothing has been stopped. What it
/// finds is not used: [`check`] looks again, under the writers' lock.
pub fn look_ahead(install: &kr_ipc::install::Store) {
    for roots in install.registered_roots().unwrap_or_default() {
        let _ = std::fs::metadata(&roots.state_root);
    }
}

/// The roots only a command registered, each looked at now: one that is not there holds nothing, and
/// one that cannot be looked at is named and left. A registration that cannot be read refuses the
/// switch, as an unreadable record of a document does: it names a root nobody can say is safe.
fn registered(
    install: &kr_ipc::install::Store,
    environments: &[&Environment],
    refusals: &mut Vec<Refusal>,
    unreached: &mut Vec<Unreached>,
) -> Vec<Registered> {
    let recorded = match install.registered_roots() {
        Ok(recorded) => recorded,
        Err(error) => {
            refusals.push(Refusal {
                store: "the roots the store's commands registered".to_owned(),
                environment: None,
                place: install.roots(),
                why: Why::Unreadable(super::said(&error)),
            });
            return Vec::new();
        }
    };
    let mut found = Vec::new();
    for roots in recorded {
        if environments
            .iter()
            .any(|known| known.host.state_root() == roots.state_root)
        {
            continue;
        }
        let not_reached = |reason: Shown| Unreached {
            runtime_root: roots.runtime_root.clone(),
            state_root: roots.state_root.clone(),
            reason,
        };
        match std::fs::metadata(&roots.state_root) {
            Ok(about) if about.is_dir() => {}
            Ok(_) => {
                unreached.push(not_reached(Shown::said("it is not a directory")));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                unreached.push(not_reached(shown!(
                    "it could not be looked at: {}",
                    Shown::io(&error)
                )));
                continue;
            }
        }
        // A root that cannot be listed holds nothing that can be looked at: named, and left whole.
        if let Err(error) = std::fs::read_dir(&roots.state_root) {
            unreached.push(not_reached(shown!(
                "it could not be listed: {}",
                Shown::io(&error)
            )));
            continue;
        }
        let Ok(host) = kr_ipc::paths::HostPaths::new(&roots.runtime_root, &roots.state_root) else {
            unreached.push(not_reached(Shown::said("its roots cannot be resolved")));
            continue;
        };
        let environment = match host.recorded_environment_id() {
            Ok(Some(environment_id)) => {
                kr_ipc::paths::HostPaths::new(&roots.runtime_root, &roots.state_root)
                    .ok()
                    .map(|again| Environment {
                        environment_id,
                        paths: host.environment(environment_id),
                        host: again,
                    })
            }
            Ok(None) => None,
            // The records of the state root itself are still looked at; only the environment's own
            // directory cannot be placed without its identity.
            Err(error) => {
                unreached.push(not_reached(shown!(
                    "its environment identity could not be looked at: {}",
                    Shown::ipc(&error)
                )));
                None
            }
        };
        found.push(Registered { host, environment });
    }
    found
}

/// What a store's places are looked for in.
struct Places<'a> {
    install: &'a kr_ipc::install::Store,
    environments: &'a [&'a Environment],
    published: &'a [(EnvironmentId, PathBuf)],
    registered: &'a [Registered],
    documents: &'a [kr_ipc::install::RecordedDocument],
}

impl Places<'_> {
    /// Where a store's paths start, for each thing of its scope there is, with the environment it is
    /// an environment's.
    fn of(&self, listed: &ReleaseStore) -> Vec<(Option<EnvironmentId>, PathBuf)> {
        let command_written = COMMAND_WRITTEN_STORES.contains(&listed.store.as_str());
        let mut found: Vec<(Option<EnvironmentId>, PathBuf)> = Vec::new();
        match listed.scope {
            StoreScope::Install => found.push((None, self.install.root().to_path_buf())),
            StoreScope::StateRoot => {
                for environment in self.environments {
                    found.push((None, environment.host.state_root().to_path_buf()));
                }
                if command_written {
                    for registered in self.registered {
                        found.push((None, registered.host.state_root().to_path_buf()));
                    }
                }
            }
            StoreScope::Environment => {
                for environment in self.environments {
                    found.push((
                        Some(environment.environment_id),
                        environment.paths.state_dir().to_path_buf(),
                    ));
                }
                if command_written {
                    for environment in self
                        .registered
                        .iter()
                        .filter_map(|r| r.environment.as_ref())
                    {
                        found.push((
                            Some(environment.environment_id),
                            environment.paths.state_dir().to_path_buf(),
                        ));
                    }
                }
            }
            StoreScope::Configuration => {
                for environment in self.environments {
                    for directory in configuration_directories(environment) {
                        found.push((Some(environment.environment_id), directory));
                    }
                    for (published_for, directory) in self.published {
                        if *published_for == environment.environment_id {
                            found.push((Some(environment.environment_id), directory.clone()));
                        }
                    }
                }
                if command_written {
                    for environment in self
                        .registered
                        .iter()
                        .filter_map(|r| r.environment.as_ref())
                    {
                        for directory in configuration_directories(environment) {
                            found.push((Some(environment.environment_id), directory));
                        }
                    }
                }
                // Every document a daemon or a command recorded, wherever its variables put it
                // and whether or not the environment it belongs to was surveyed.
                for document in self.documents {
                    if let Some(directory) = document.path.parent() {
                        found.push((Some(document.environment), directory.to_path_buf()));
                    }
                }
            }
            StoreScope::Unknown => {}
        }
        found.sort_by(|left, right| left.1.cmp(&right.1));
        found.dedup();
        found
    }
}

/// Where an environment's configuration document can be, apart from where its daemon said: with the
/// rest of its state, where this process's own environment says, and where an account with a home
/// puts it by default.
///
/// A daemon is started again with the variables it had, so it reads where it said. These are the
/// places a daemon started later by a command of this process's environment, or by the account's
/// service manager, reads it, which are looked at for the same reason: the document that daemon
/// loads decides the owner's ceilings. A daemon that is not running said nothing, and one started
/// later with variables that are neither this process's nor the account's is not covered.
fn configuration_directories(environment: &Environment) -> Vec<PathBuf> {
    let mut found = vec![environment.paths.state_dir().to_path_buf()];
    let documented = kr_protocol::hostinfo::configuration::document_path(
        environment.paths.state_dir(),
        environment.host.state_root(),
        environment.environment_id,
    );
    if let Some(directory) = documented.parent() {
        found.push(directory.to_path_buf());
    }
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        found.push(
            PathBuf::from(home)
                .join(".config")
                .join("kalareach")
                .join("environments")
                .join(kr_ipc::paths::short_prefix(environment.environment_id)),
        );
    }
    found
}

/// The files a store names under a directory: the one file, or every record of an extension in a
/// directory. A directory that is not there holds no record; one that cannot be listed is a store
/// that cannot be read.
fn files(directory: &Path, listed: &ReleaseStore) -> Result<Vec<PathBuf>, Shown> {
    let Some((inner, extension)) = listed.records() else {
        return Ok(vec![directory.join(&listed.path)]);
    };
    let entries = match std::fs::read_dir(directory.join(inner)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(shown!(
                "the directory of its records could not be listed: {}",
                Shown::io(&error)
            ));
        }
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            shown!(
                "the directory of its records could not be listed: {}",
                Shown::io(&error)
            )
        })?;
        let path = entry.path();
        let record = path
            .extension()
            .is_some_and(|candidate| candidate == extension)
            && path
                .file_name()
                .is_some_and(|name| !name.to_string_lossy().starts_with('.'));
        if record {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

/// Reads the version one file records and says why the target does not read it, when it does not.
fn look(listed: &ReleaseStore, file: &Path, carries: bool) -> Option<Why> {
    let found = match read(listed, file) {
        Ok(None) => return None,
        Ok(Some(found)) => found,
        Err(reason) => return Some(Why::Unreadable(reason)),
    };
    // The one store an update itself migrates: it brings a registry that is behind forward to the
    // version it reads, so that is the version the target meets. A rollback brings nothing forward.
    let brought_to = (carries
        && listed.store == "registry"
        && (kr_controller::registry::OLDEST_SCHEMA_VERSION
            ..kr_controller::registry::SCHEMA_VERSION)
            .contains(&i64::from(found)))
    .then(|| u32::try_from(kr_controller::registry::SCHEMA_VERSION).unwrap_or(u32::MAX));
    let met = brought_to.unwrap_or(found);
    if (listed.migrates_from..=listed.version).contains(&met) {
        None
    } else {
        Some(Why::Version {
            found,
            brought_to,
            lowest: listed.migrates_from,
            highest: listed.version,
            schema: matches!(
                listed.recording,
                Recording::SqliteTable { .. } | Recording::SqliteUserVersion
            ),
        })
    }
}

/// The version one file records, or `None` where there is no such file.
fn read(listed: &ReleaseStore, file: &Path) -> Result<Option<u32>, Shown> {
    use kr_controller::registry::{RecordedIn, recorded_version};

    let number = |found: Option<i64>| {
        found
            .map(|found| {
                u32::try_from(found)
                    .map_err(|_| Shown::said("it records a version that is not a number"))
            })
            .transpose()
    };
    match &listed.recording {
        Recording::SqliteTable { table } => {
            number(recorded_version(file, RecordedIn::Table(table)).map_err(refused)?)
        }
        Recording::SqliteUserVersion => {
            number(recorded_version(file, RecordedIn::UserVersion).map_err(refused)?)
        }
        Recording::JsonMember { member, absent } => json(
            file,
            member,
            *absent,
            listed.scope == StoreScope::Configuration,
        ),
        Recording::CborMember { member, absent } => cbor(file, member, *absent),
        Recording::Unknown => Err(Shown::said("its way of recording its version is not known")),
    }
}

/// What a database's refusal to say its version says.
fn refused(refusal: kr_controller::registry::VersionRefusal) -> Shown {
    use kr_controller::registry::VersionRefusal;

    match refusal {
        VersionRefusal::NotARegularFile => Shown::said("it is not a regular file"),
        VersionRefusal::SharedMemoryNotARegularFile => {
            Shown::said("the shared-memory file beside it is not a regular file")
        }
        VersionRefusal::Unlooked(error) => {
            shown!("it could not be looked at: {}", Shown::io(&error))
        }
        VersionRefusal::LogNotTaken => Shown::said(
            "its write-ahead log could not be taken into it, so what a daemon left in the log is \
             not known",
        ),
        VersionRefusal::Unopened => Shown::said("it could not be opened to be read"),
        VersionRefusal::NoTable => {
            Shown::said("it has no table that records a version, or is not a database")
        }
        VersionRefusal::NoVersion => Shown::said("it records no version"),
        VersionRefusal::SeveralVersions => Shown::said("it records more than one version"),
        VersionRefusal::NotAVersion => Shown::said("it records a version that is not a number"),
        VersionRefusal::Unread => Shown::said("its version could not be read"),
    }
}

/// A member of a record: a whole number, or anything else.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Member {
    Number(u64),
    Other(serde::de::IgnoredAny),
}

/// Reads the version a JSON record states in `member`; `absent` where it states none. A record that
/// cannot be read as a JSON object with a whole number there is refused, unless `lenient`, which is
/// the configuration document: no release can use one it cannot read (a release that holds the
/// fail-closed rule fails closed on it, and an earlier one took the product defaults), so a
/// document that states no version it can make out has none to refuse a switch for. A whole number it can
/// make out is a version like any other, and one outside the range, or too large to be any
/// release's, is refused.
fn json(file: &Path, member: &str, absent: u32, lenient: bool) -> Result<Option<u32>, Shown> {
    let bytes = match kr_ipc::install::read_regular_file(file, super::RECORD_LIMIT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) if lenient => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err(Shown::said(
                "it is not a regular file, or is larger than a record of its kind",
            ));
        }
        Err(error) => {
            return Err(shown!("it could not be read: {}", Shown::io(&error)));
        }
    };
    let Ok(document) = serde_json::from_slice::<std::collections::BTreeMap<String, Member>>(&bytes)
    else {
        return if lenient {
            Ok(None)
        } else {
            Err(Shown::said("it is not a JSON object"))
        };
    };
    match document.get(member) {
        None => Ok(Some(absent)),
        Some(Member::Number(stated)) => u32::try_from(*stated).map(Some).map_err(|_| {
            Shown::said("it records a version larger than any version a release reads")
        }),
        Some(Member::Other(_)) if lenient => Ok(None),
        Some(Member::Other(_)) => Err(Shown::said(
            "the member that records its version is not a whole number",
        )),
    }
}

/// Reads the version a record in KR-CBOR-1 states in `member`; `absent` where it states none. A
/// record that cannot be read as a map with a whole number there is refused.
fn cbor(file: &Path, member: &str, absent: u32) -> Result<Option<u32>, Shown> {
    use kr_cbor::CanonicalValue;

    let bytes = match kr_ipc::install::read_regular_file(file, super::RECORD_LIMIT) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err(Shown::said(
                "it is not a regular file, or is larger than a record of its kind",
            ));
        }
        Err(error) => {
            return Err(shown!("it could not be read: {}", Shown::io(&error)));
        }
    };
    let limits = kr_cbor::Limits {
        max_message_len: bytes.len(),
        max_items: bytes.len(),
        max_collection_len: bytes.len(),
        ..kr_cbor::Limits::DEFAULT
    };
    let Ok(CanonicalValue::Map(members)) = kr_cbor::decode(&bytes, &limits) else {
        return Err(Shown::said("it is not a map in the canonical encoding"));
    };
    match members.get(member) {
        None => Ok(Some(absent)),
        Some(CanonicalValue::Integer(stated)) => stated
            .as_u64()
            .ok_or_else(|| Shown::said("the member that records its version is not a whole number"))
            .and_then(|stated| {
                u32::try_from(stated).map(Some).map_err(|_| {
                    Shown::said("it records a version larger than any version a release reads")
                })
            }),
        Some(_) => Err(Shown::said(
            "the member that records its version is not a whole number",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(directory: &Path, name: &str, text: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, text).expect("a record");
        path
    }

    /// A release that lists `shell-entries` and `machine-group`, at versions 1 to 1.
    fn target() -> ReleaseManifest {
        let listed = |name: &str, scope: &str, path: &str| {
            serde_json::json!({
                "store": name,
                "scope": scope,
                "path": path,
                "recording": { "kind": "json_member", "member": "version", "absent": 0 },
                "version": 1,
                "migrates_from": 1,
            })
        };
        let document = serde_json::json!({
            "signed": {
                "_type": "kalareach-release",
                "release": "0.2.0+bbbbbbbbbbbb",
                "sequence": "2",
                "commit": "4254aa6e62e585478ff8dcff5518f23c7263f4ce",
                "target": "aarch64-apple-darwin",
                "os_floor": { "system": "macos", "version": "14.0" },
                "protocol_version": { "major": 0, "minor": 48, "patch": 0 },
                "public_majors": [1],
                "retained_levels": ["0.48"],
                "shells": [],
                "stores": [
                    listed("shell-entries", "state_root", "shell-entries.json"),
                    listed("machine-group", "environment", "machine-group"),
                ],
                "files": [],
            },
            "signatures": [],
        });
        ReleaseManifest::read_document(document.to_string().as_bytes()).expect("a manifest")
    }

    /// KR-REQ-26.10: a root only a command registered is looked at when the check runs, under the
    /// writers' lock, and not when it was listed: a root that did not exist then can exist now. In it
    /// the stores a command writes are read by name, and a daemon's store of the same recording kind
    /// is not; a root that cannot be looked at is named and does not refuse the switch.
    #[test]
    fn a_registered_root_is_looked_at_when_the_check_runs_and_only_for_the_stores_a_command_writes()
    {
        use std::os::unix::ffi::OsStrExt as _;

        let directory = tempfile::tempdir().expect("a directory");
        let store = kr_ipc::install::Store::at(directory.path().join("host"));
        store.create_directories().expect("the store");
        let state = directory.path().join("state");
        let mut registration = directory.path().join("run").as_os_str().as_bytes().to_vec();
        registration.push(0);
        registration.extend_from_slice(state.as_os_str().as_bytes());
        kr_ipc::paths::create_private_directory(&store.roots()).expect("the records");
        kr_ipc::paths::write_owner_only_file(
            &store.roots().join("0123456789abcdef.registered"),
            &registration,
        )
        .expect("a registration");
        let target = target();
        let writers = store
            .try_lock_writers()
            .expect("asks")
            .expect("no command is writing");

        // Registered when the root was not there: nothing to look at, and nothing to name.
        let checked = check(&target, &store, &[], &[], true, &writers);
        assert!(checked.refusals.is_empty() && checked.unreached.is_empty());

        // The command made the root and wrote its record after that: the check, which runs later,
        // finds it. A daemon's store in the same root, at a version the target does not read, is not
        // this store's to refuse a switch for.
        kr_ipc::paths::create_private_directory(&state).expect("the root");
        let environment_id = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        kr_ipc::paths::write_owner_only_file(
            &state.join("environment-id"),
            format!("{environment_id}\n").as_bytes(),
        )
        .expect("an identity");
        let paths = kr_ipc::paths::HostPaths::new(directory.path().join("run"), &state)
            .expect("the roots")
            .environment(environment_id);
        kr_ipc::paths::create_private_directory(paths.state_dir()).expect("the environment");
        kr_ipc::paths::write_owner_only_file(
            &state.join("shell-entries.json"),
            br#"{"version": 5}"#,
        )
        .expect("a record");
        kr_ipc::paths::write_owner_only_file(
            &paths.state_dir().join("machine-group"),
            br#"{"version": 9}"#,
        )
        .expect("a daemon's");
        let checked = check(&target, &store, &[], &[], true, &writers);
        assert_eq!(checked.refusals.len(), 1, "one record is out of range");
        assert!(
            checked.refusals[0].place.ends_with("shell-entries.json"),
            "and it is the command's"
        );

        // An identity that cannot be read puts the environment out of reach, named, and the records
        // of the state root itself are still looked at.
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                state.join("environment-id"),
                std::fs::Permissions::from_mode(0o666),
            )
            .expect("wider than owner-only");
        }
        let checked = check(&target, &store, &[], &[], true, &writers);
        assert_eq!(checked.refusals.len(), 1, "the state root's record is read");
        assert!(checked.refusals[0].place.ends_with("shell-entries.json"));
        assert_eq!(checked.unreached.len(), 1, "and the identity is named");

        // A root that is a file cannot be looked at: named, not refused.
        std::fs::remove_dir_all(&state).expect("the root goes");
        std::fs::write(&state, b"not a directory").expect("a file");
        let checked = check(&target, &store, &[], &[], true, &writers);
        assert!(checked.refusals.is_empty());
        assert_eq!(checked.unreached.len(), 1);
        assert_eq!(checked.unreached[0].state_root, state);

        // A registration that cannot be read refuses the switch, whatever the others say: the root
        // it names is not known to be safe.
        let damaged = store.roots().join("fedcba9876543210.registered");
        std::fs::write(&damaged, &registration).expect("a registration");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o666))
                .expect("wider than owner-only");
        }
        let checked = check(&target, &store, &[], &[], true, &writers);
        assert_eq!(checked.refusals.len(), 1, "{:?}", checked.refusals.len());
        assert!(checked.refusals[0].store.contains("registered"));
        assert!(
            checked.refusals[0].place.ends_with("roots"),
            "and it names the records' directory"
        );
        assert!(matches!(&checked.refusals[0].why, Why::Unreadable(_)));
    }

    /// A JSON record states its version in its member; one that states none is at the version the
    /// manifest gives for that, and one whose member is not a whole number, or that is not JSON or
    /// not an object, cannot be shown to be in range and is refused. The configuration document is
    /// the exception, which no release can use when it cannot read it. A file that is
    /// not there is not checked.
    #[test]
    fn a_json_record_is_read_by_its_member_and_what_cannot_be_read_is_refused() {
        let directory = tempfile::tempdir().expect("a directory");
        let at = |text: &str| record(directory.path(), "record.json", text);
        let version =
            |path: &Path, absent: u32, lenient: bool| json(path, "version", absent, lenient);

        let read = |path: &Path, absent: u32, lenient: bool| version(path, absent, lenient).ok();
        assert_eq!(read(&at(r#"{"version": 3}"#), 0, false), Some(Some(3)));
        assert_eq!(read(&at(r#"{"other": 1}"#), 0, false), Some(Some(0)));
        assert_eq!(read(&at(r#"{"other": 1}"#), 1, true), Some(Some(1)));
        for refused in [
            r#"{"version": "3"}"#,
            r#"{"version": -1}"#,
            "[1]",
            "{ not JSON",
        ] {
            assert!(
                version(&at(refused), 0, false).is_err(),
                "{refused} cannot be read"
            );
            assert_eq!(
                read(&at(refused), 1, true),
                Some(None),
                "the configuration document is not refused for it: {refused}"
            );
        }
        // A whole number too large for any release to read is refused, not read as no version or as
        // the largest there is, which a range may reach.
        for lenient in [false, true] {
            assert!(
                version(&at(r#"{"version": 4294967296}"#), 0, lenient).is_err(),
                "a version no release reads is refused (lenient: {lenient})"
            );
        }
        assert_eq!(
            read(&directory.path().join("absent.json"), 0, false),
            Some(None)
        );
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(at(r#"{"version": 1}"#), &link).expect("a link");
        assert!(
            version(&link, 0, false).is_err(),
            "a link is refused, not followed"
        );
    }

    /// A database records its version in a table or in SQLite's own `user_version`; one that
    /// records none, several, or is not a database cannot be shown to be in range and is refused,
    /// and one that is not there is not checked.
    #[test]
    fn a_database_is_read_by_its_table_or_its_user_version_and_what_cannot_be_read_is_refused() {
        use kr_controller::registry::{RecordedIn, recorded_version};

        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("store.sqlite");
        let connection = rusqlite_open(&path);
        connection
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (4);
                 PRAGMA user_version = 9;",
            )
            .expect("a database");
        drop(connection);
        let table = || recorded_version(&path, RecordedIn::Table("schema_version"));
        assert_eq!(table().expect("reads"), Some(4));
        assert_eq!(
            recorded_version(&path, RecordedIn::UserVersion).expect("reads"),
            Some(9)
        );
        let both = rusqlite_open(&path);
        both.execute("INSERT INTO schema_version (version) VALUES (5)", [])
            .expect("a second row");
        drop(both);
        assert!(table().is_err(), "two versions are refused");
        assert!(
            recorded_version(&path, RecordedIn::Table("no_such_table")).is_err(),
            "a table that is not there is refused"
        );
        let empty = directory.path().join("empty.sqlite");
        std::fs::write(&empty, b"").expect("an empty file");
        assert!(recorded_version(&empty, RecordedIn::Table("schema_version")).is_err());
        assert_eq!(
            recorded_version(
                &directory.path().join("absent.sqlite"),
                RecordedIn::Table("schema_version")
            )
            .expect("reads"),
            None
        );
    }

    /// A directory of records is listed, by the extension the store names, and one that cannot be
    /// listed is a store that cannot be read: only a directory that is not there holds no record.
    #[test]
    fn a_directory_of_records_that_cannot_be_listed_is_refused_and_one_that_is_not_there_is_not() {
        let listed = |path: &str| ReleaseStore {
            store: "records".to_owned(),
            scope: StoreScope::StateRoot,
            path: path.to_owned(),
            recording: Recording::JsonMember {
                member: "version".to_owned(),
                absent: 0,
            },
            version: 1,
            migrates_from: 0,
        };
        let directory = tempfile::tempdir().expect("a directory");
        let records = directory.path().join("records");
        assert!(
            files(directory.path(), &listed("records/*.json"))
                .expect("no directory holds no record")
                .is_empty()
        );
        std::fs::create_dir(&records).expect("a directory");
        record(&records, "one.json", "{}");
        record(&records, "two.answer", "");
        record(&records, ".hidden.json", "{}");
        record(&records, "note.txt", "");
        assert_eq!(
            files(directory.path(), &listed("records/*.json")).expect("lists"),
            vec![records.join("one.json")]
        );
        assert_eq!(
            files(directory.path(), &listed("records/*.answer")).expect("lists"),
            vec![records.join("two.answer")]
        );
        // A file where the directory belongs cannot be listed.
        std::fs::remove_dir_all(&records).expect("removed");
        std::fs::write(&records, b"not a directory").expect("a file");
        assert!(files(directory.path(), &listed("records/*.json")).is_err());
    }

    /// A record in KR-CBOR-1 states its version in its member, as a JSON record does: one that
    /// states none is at the version the manifest gives for that, and one that is not a map, whose
    /// member is not a whole number or is larger than any release reads cannot be shown to be in
    /// range and is refused. A file that is not there is not checked.
    #[test]
    fn a_cbor_record_is_read_by_its_member_and_what_cannot_be_read_is_refused() {
        use kr_cbor::{CanonicalMap, CanonicalValue, encode};

        let directory = tempfile::tempdir().expect("a directory");
        let written = |name: &str, value: CanonicalValue| {
            let path = directory.path().join(name);
            std::fs::write(&path, encode(&value)).expect("a record");
            path
        };
        let map = |entries: Vec<(&str, CanonicalValue)>| {
            CanonicalValue::Map(
                CanonicalMap::from_entries(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key.to_owned(), value)),
                )
                .expect("a map"),
            )
        };
        let integer = |value: i128| CanonicalValue::integer(value).expect("an integer");
        let read = |path: &Path| cbor(path, "version", 0).ok();
        assert_eq!(
            read(&written("one", map(vec![("version", integer(3))]))),
            Some(Some(3))
        );
        assert_eq!(
            read(&written("none", map(vec![("other", integer(1))]))),
            Some(Some(0))
        );
        for (name, refused) in [
            ("text", map(vec![("version", CanonicalValue::text("3"))])),
            ("negative", map(vec![("version", integer(-1))])),
            ("large", map(vec![("version", integer(4_294_967_296))])),
            ("array", CanonicalValue::Array(vec![integer(1)])),
        ] {
            assert!(
                cbor(&written(name, refused), "version", 0).is_err(),
                "{name} cannot be read"
            );
        }
        let torn = directory.path().join("torn");
        std::fs::write(&torn, [0xa1, 0x67]).expect("a torn record");
        assert!(cbor(&torn, "version", 0).is_err());
        assert_eq!(
            cbor(&directory.path().join("absent"), "version", 0).ok(),
            Some(None)
        );
    }

    fn rusqlite_open(path: &Path) -> rusqlite::Connection {
        rusqlite::Connection::open(path).expect("opens")
    }
}
