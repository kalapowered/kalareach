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

use super::inventory::Environment;
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

/// Looks at every store `target` lists, where the manifest says it is, and returns each that is at
/// a version the target does not read, with those [`unlookable`] too.
///
/// `environments` are the environments whose daemons have stopped and whose locks are held.
#[must_use]
pub fn check(
    target: &ReleaseManifest,
    install: &kr_ipc::install::Store,
    environments: &[&Environment],
) -> Vec<Refusal> {
    let mut refusals = unlookable(target);
    for listed in &target.stores {
        if listed.scope == StoreScope::Unknown || listed.recording == Recording::Unknown {
            continue;
        }
        for (environment, directory) in directories(listed.scope, install, environments) {
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
                        if let Some(why) = look(listed, &file) {
                            refuse(file, why);
                        }
                    }
                }
                Err(reason) => refuse(directory.join(&listed.path), Why::Unreadable(reason)),
            }
        }
    }
    refusals
}

/// Where a scope's paths start, for each thing of that scope there is, with the environment it is
/// an environment's.
fn directories(
    scope: StoreScope,
    install: &kr_ipc::install::Store,
    environments: &[&Environment],
) -> Vec<(Option<EnvironmentId>, PathBuf)> {
    let mut found: Vec<(Option<EnvironmentId>, PathBuf)> = Vec::new();
    match scope {
        StoreScope::Install => found.push((None, install.root().to_path_buf())),
        StoreScope::StateRoot => {
            for environment in environments {
                found.push((None, environment.host.state_root().to_path_buf()));
            }
        }
        StoreScope::Environment => {
            for environment in environments {
                found.push((
                    Some(environment.environment_id),
                    environment.paths.state_dir().to_path_buf(),
                ));
            }
        }
        StoreScope::Configuration => {
            for environment in environments {
                for directory in configuration_directories(environment) {
                    found.push((Some(environment.environment_id), directory));
                }
            }
        }
        StoreScope::Unknown => {}
    }
    found.sort_by(|left, right| left.1.cmp(&right.1));
    found.dedup();
    found
}

/// Where an environment's configuration document can be: with the rest of its state, where this
/// process's own environment says, and where an account with a home puts it by default. The
/// daemon that reads it may have been started with an environment of its own, so each is looked at;
/// one started with variables of its own that put the document somewhere else is not covered.
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
fn look(listed: &ReleaseStore, file: &Path) -> Option<Why> {
    let found = match read(listed, file) {
        Ok(None) => return None,
        Ok(Some(found)) => found,
        Err(reason) => return Some(Why::Unreadable(reason)),
    };
    // The one store an update itself migrates: it brings a registry that is behind forward to the
    // version it reads, so that is the version the target meets.
    let brought_to = (listed.store == "registry"
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
/// the configuration document: every release loads one it cannot read as defaults, so a document
/// that states no version it can make out has none to refuse a switch for. A whole number it can
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

    /// A JSON record states its version in its member; one that states none is at the version the
    /// manifest gives for that, and one whose member is not a whole number, or that is not JSON or
    /// not an object, cannot be shown to be in range and is refused. The configuration document is
    /// the exception, which every release loads as defaults when it cannot read it. A file that is
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
