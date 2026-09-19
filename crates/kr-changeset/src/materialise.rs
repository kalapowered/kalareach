//! Independent materialisations of one exact version, and the results recorded against them.
//!
//! Section 14: "Tests/reviewer sessions use independent materializations of that exact version, so
//! the original agent can continue without changing their inputs." Independent means what it says:
//! the content is written out of this service's own content-addressed store into a private
//! directory of this service's own, and neither the repository nor the workspace the version came
//! from is touched. The agent whose working tree was captured can keep editing it.
//!
//! # What a result may and may not say
//!
//! A result must not attest that the unmodified version passed when the tested source was changed
//! or cannot be established. So recording one **re-reads the materialisation** and compares it with
//! the version:
//!
//! * identical — the result attests the input version;
//! * different — this host records a **derived version** with its own identity and the result
//!   attests that, naming the input version beside it;
//! * unreadable, or holding something this host cannot represent — the result says
//!   [`TestedSource::Indeterminate`] and attests nothing.
//!
//! Every one of the three is recorded as evidence against the input version **and** against the
//! version it attests, so retention accounts for it before anything is deleted.
//!
//! What this establishes, said plainly because the difference matters: this host reads the
//! directory when the materialisation is made and again when the result is recorded. It does not
//! watch it while the run is happening. A run that changed a file, tested the change and put the
//! file back reads as unmodified from here, and one that finished its tests and then changed a
//! file reads as modified. Every attestation says so in its own words. Binding a result to the
//! bytes a command actually read needs a host that owns the execution, which this one does not.
//!
//! The grant and the secret rules apply to the re-read as well as to the capture: a run that wrote
//! a credential into its own copy does not get it stored in a derived version.

use std::io::{Read as _, Write as _};

use kr_protocol::changeset::{
    CapturedPath, ChangeSetVersionRecord, ContentOrigin, ExecutionReceipt, MaterialisationPurpose,
    MaterialisationRecord, MaterialisationResult, ObservedPath, OutputReference, PathClass,
    Provenance, SourceConsistency, TestedSource, ToolIdentity, VersionRef,
};
use kr_protocol::ids::{ChangeSetVersion, MaterialisationId};
use kr_protocol::project::{ChangeKind, FilesystemIdentity};
use kr_protocol::scalars::{Nullable, U64};
use kr_transfer::authority::ObjectKind;
use kr_transfer::{AuthorisedDirectory, ObjectPolicy, RelativeName};

use crate::error::{ChangeSetError, Result};
use crate::grant::{self, GrantDecision};
use crate::service::{ChangeSetService, MATERIALISATIONS_DIRECTORY, decode_stored, encode_stored};
use crate::store::{MaterialisationRow, ResultRow};
use crate::version::Manifest;

/// What a materialisation cannot promise, in this host's own words.
#[must_use]
pub fn limitations() -> Vec<String> {
    vec![
        "this materialisation holds the version's source exactly and nothing else: network \
         services, installed dependencies, secrets and graphical state are external inputs, so an \
         identical source does not promise an identical run"
            .to_owned(),
        "a run that changes this directory changes what a result about it can attest; this host \
         re-reads the directory when a result is recorded and says so"
            .to_owned(),
    ]
}

/// Writes one exact version into a private directory of this service's own.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownVersion`] when there is no such version, and
/// [`ChangeSetError::StorageUnavailable`] when the directory cannot be written.
pub fn materialise(
    service: &ChangeSetService,
    version: VersionRef,
    purpose: MaterialisationPurpose,
    label: &str,
) -> Result<MaterialisationRecord> {
    let record = service.record(version.change_set_id, Some(version.version))?;
    let manifest = service.manifest(version.change_set_id, version.version)?;
    let materialisation_id = MaterialisationId::new(kr_ipc::new_uuid());
    let parent = service
        .root()
        .subdirectory(&RelativeName::parse(MATERIALISATIONS_DIRECTORY)?)?;
    let directory_name = materialisation_id.to_string();
    let name = RelativeName::parse(&directory_name)?;
    // Made, not opened. Creating a directory is exclusive on every platform this runs on: it
    // fails when the name is taken, whatever is at it. That is what establishes that the
    // directory a release later empties is the one this host made, rather than something that
    // happened to be at the name and looked empty at the moment it was checked.
    parent.handle().create_dir(name.as_str()).map_err(|error| {
        ChangeSetError::StorageUnavailable {
            detail: format!(
                "this host makes a materialisation's directory rather than adopting one, and it \
                 could not make this one: {error}"
            )
            .into(),
        }
    })?;
    let directory = parent.subdirectory(&name)?;
    let identity = directory.identity();
    let created_at_ms = kr_ipc::now_ms();
    let mut held = MaterialisationRecord {
        materialisation_id,
        version,
        content_digest: record.content_digest,
        environment_id: service.environment_id(),
        purpose,
        label: label.to_owned(),
        directory_path: parent.host_path(&name).display().to_string(),
        filesystem_identity: FilesystemIdentity {
            device: U64::new(identity.device),
            file_id: U64::new(identity.file_id),
        },
        paths_written: U64::new(0),
        unapplied: Vec::new(),
        observed: Vec::new(),
        created_at_ms,
        released_at_ms: Nullable(None),
    };
    // The row goes in **before** a byte is written, and it refuses when the version is no longer
    // there. A directory written first and recorded afterwards is a directory whose version a
    // deletion could take away in between, leaving files nothing accounts for.
    let recorded = service
        .locked()?
        .insert_materialisation(&MaterialisationRow {
            materialisation_id,
            change_set_id: version.change_set_id,
            version: version.version,
            purpose,
            record: encode_stored(&held)?,
            directory_name: directory_name.clone(),
            identity,
            created_at_ms,
            released_at_ms: None,
        });
    if let Err(error) = recorded {
        // The row is what accounts for this directory. Without one there is nothing to release it
        // later, so the empty directory this host had just made goes now. It holds nothing: not a
        // byte is written until the row is in.
        drop(directory);
        let _ = parent.handle().remove_dir(&directory_name);
        let _ = parent.sync();
        return Err(error);
    }
    let mut written = 0_u64;
    for entry in &manifest.paths {
        match write_path(service, &directory, entry) {
            Ok(observed) => {
                written += 1;
                held.observed.push(observed);
            }
            Err(_) => held.unapplied.push(entry.path.clone()),
        }
    }
    directory.sync()?;
    held.paths_written = U64::new(written);
    service
        .locked()?
        .set_materialisation_record(materialisation_id, &encode_stored(&held)?)?;
    Ok(held)
}

/// Writes one path into a materialisation, creating the directories above it.
///
/// The bytes are written exactly as the store holds them: nothing translates a line ending,
/// because a captured tree holds content as it was and a materialisation that rewrote it would be
/// a materialisation of something else. The executable bit is the one permission a captured tree
/// carries, and it is set from the version rather than from whatever the platform defaults to.
fn write_path(
    service: &ChangeSetService,
    directory: &AuthorisedDirectory,
    entry: &CapturedPath,
) -> Result<ObservedPath> {
    let bytes = service.objects().get(entry.content_digest)?;
    let name = RelativeName::parse(&entry.path)?;
    let components = name.components();
    let (leaf, parents) =
        components
            .split_last()
            .ok_or_else(|| ChangeSetError::StorageUnavailable {
                detail: "a captured path has no name".into(),
            })?;
    // Each level is created against the authority the level above returned, so nothing depends on
    // a prefix resolved after it was checked.
    let mut here = clone_handle(directory)?;
    for component in parents {
        here = here.create_subdirectory(&RelativeName::parse(component)?)?;
    }
    let leaf_name = RelativeName::parse(leaf)?;
    // A version cannot hold one path twice, so an occupied name here is something this host did
    // not put there. It is reported rather than replaced.
    let mut file = here.create_new(&leaf_name)?;
    file.handle_mut()
        .write_all(&bytes)
        .map_err(ChangeSetError::storage)?;
    file.handle_mut()
        .sync_all()
        .map_err(ChangeSetError::storage)?;
    set_executable(&file, entry.executable)?;
    here.sync()?;
    // What this host left behind, so a re-read can tell a file nobody touched from one a run
    // rewrote with the same bytes: the object, its length, and when it was last written.
    let identity = file.identity();
    Ok(ObservedPath {
        path: entry.path.clone(),
        device: U64::new(identity.device),
        file_id: U64::new(identity.file_id),
        byte_len: U64::new(bytes.len() as u64),
        written_at_nanos: Nullable(written_at(&file).map(U64::new)),
    })
}

/// Returns when a file was last written, as the platform counts it.
///
/// A whole number of nanoseconds since the epoch, so the value can be recorded and compared
/// later. A platform that will not say answers nothing, and the comparison then rests on the
/// identity and the length alone, which is said where the limit is stated.
fn written_at(file: &kr_transfer::AuthorisedFile) -> Option<u64> {
    let modified = file.handle().metadata().ok()?.modified().ok()?;
    let system: std::time::SystemTime = modified.into_std();
    let since = system.duration_since(std::time::UNIX_EPOCH).ok()?;
    u64::try_from(since.as_nanos()).ok()
}

/// Returns a second authority over the same open directory.
///
/// The handle is duplicated rather than the path reopened, so the walk down a captured path never
/// resolves a name a second time.
fn clone_handle(directory: &AuthorisedDirectory) -> Result<AuthorisedDirectory> {
    let handle = directory
        .handle()
        .try_clone()
        .map_err(ChangeSetError::storage)?;
    Ok(AuthorisedDirectory::from_handle(
        directory.environment_id(),
        handle,
        directory.display_path().to_path_buf(),
    )?)
}

/// Sets or clears the executable bit on a materialised file.
#[cfg(unix)]
fn set_executable(file: &kr_transfer::AuthorisedFile, executable: bool) -> Result<()> {
    use cap_std::fs::PermissionsExt as _;
    if !executable {
        return Ok(());
    }
    let metadata = file.handle().metadata().map_err(ChangeSetError::storage)?;
    let mode = metadata.permissions().mode();
    // Only where the file is already readable and writable by its owner: a captured tree carries
    // one bit, and this adds it rather than replacing the permissions the service's own directory
    // policy set.
    let permissions = cap_std::fs::Permissions::from_mode(mode | 0o100);
    file.handle()
        .set_permissions(permissions)
        .map_err(ChangeSetError::storage)
}

/// Does nothing: this platform has no executable bit on a file.
#[cfg(not(unix))]
fn set_executable(_file: &kr_transfer::AuthorisedFile, _executable: bool) -> Result<()> {
    Ok(())
}

/// What re-reading one materialisation established.
#[derive(Clone, Debug)]
pub enum Reread {
    /// The directory held exactly the version, at exactly the objects this host wrote.
    Unmodified,
    /// It held something else, and this is what, with every byte already in the content store.
    Modified(Manifest),
    /// This host could not establish what it held.
    Indeterminate(String),
}

/// Re-reads one materialisation and says whether it still holds the version.
///
/// Every file is read **once**, with its identity and length compared across its own read, so the
/// digest, the length, the content class and the mode a derived version records all describe the
/// same reading.
///
/// Three things make the source indeterminate rather than merely different: something this host
/// cannot represent in a version, a name or a directory it cannot read, and a path a rule would
/// have kept out that the run put there — because a version that quietly left that path out would
/// say the run used a tree that did not hold it.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownMaterialisation`] when there is no such materialisation.
pub fn reread(
    service: &ChangeSetService,
    materialisation_id: MaterialisationId,
) -> Result<(MaterialisationRow, Reread, Vec<ObservedPath>)> {
    let row = service
        .locked()?
        .materialisation(materialisation_id)?
        .ok_or_else(|| ChangeSetError::UnknownMaterialisation {
            detail: format!("no materialisation {materialisation_id}").into(),
        })?;
    let original = service.manifest(row.change_set_id, row.version)?;
    let record = service.record(row.change_set_id, Some(row.version))?;
    let held: MaterialisationRecord = decode_stored(&row.record)?;
    let parent = service
        .root()
        .subdirectory(&RelativeName::parse(MATERIALISATIONS_DIRECTORY)?)?;
    let directory = match parent.subdirectory(&RelativeName::parse(&row.directory_name)?) {
        Ok(directory) => directory,
        Err(error) => {
            return Ok((
                row,
                Reread::Indeterminate(format!(
                    "this host could not open the materialisation it made: {error}"
                )),
                Vec::new(),
            ));
        }
    };
    if directory.identity() != row.identity {
        return Ok((
            row,
            Reread::Indeterminate(
                "the directory at this materialisation's name is not the object this host made"
                    .to_owned(),
            ),
            Vec::new(),
        ));
    }
    let mut found = Manifest {
        paths: Vec::new(),
        exclusions: Vec::new(),
        deletions: Vec::new(),
    };
    let mut budget = Budget {
        bytes: kr_protocol::changeset::MAX_CAPTURE_BYTES,
        entries: crate::capture::MAX_WALK_ENTRIES,
    };
    let mut observed = Vec::new();
    if let Err(detail) = walk(
        service,
        &directory,
        "",
        &original,
        &record.policy.grant,
        &mut found,
        &mut budget,
        &mut observed,
        0,
    )? {
        return Ok((row, Reread::Indeterminate(detail), observed));
    }
    found.canonicalise();
    if same_content(&original, &found) && same_objects(&held.observed, &observed) {
        Ok((row, Reread::Unmodified, observed))
    } else {
        Ok((row, Reread::Modified(found), observed))
    }
}

/// How much of a re-read's budget is left.
struct Budget {
    bytes: u64,
    entries: usize,
}

/// Returns true when two manifests hold the same paths with the same content and the same mode.
fn same_content(left: &Manifest, right: &Manifest) -> bool {
    if left.paths.len() != right.paths.len() {
        return false;
    }
    left.paths.iter().zip(&right.paths).all(|(a, b)| {
        a.path == b.path && a.content_digest == b.content_digest && a.executable == b.executable
    })
}

/// Returns true when every path is still the object this host wrote, of the same length, last
/// written at the same instant.
///
/// This is what tells a file nobody touched from one a run rewrote with the same bytes: rewriting
/// a file changes the instant the platform records for it, and replacing it changes the object.
/// What it does not catch is a run that restored the object, the length **and** the instant, which
/// takes deliberate work, and a platform that reports no instant at all.
fn same_objects(before: &[ObservedPath], after: &[ObservedPath]) -> bool {
    if before.len() != after.len() {
        return false;
    }
    let mut before: Vec<&ObservedPath> = before.iter().collect();
    let mut after: Vec<&ObservedPath> = after.iter().collect();
    before.sort_by(|a, b| a.path.cmp(&b.path));
    after.sort_by(|a, b| a.path.cmp(&b.path));
    before.iter().zip(&after).all(|(a, b)| {
        a.path == b.path
            && a.device == b.device
            && a.file_id == b.file_id
            && a.byte_len == b.byte_len
            && a.written_at_nanos == b.written_at_nanos
    })
}

/// Reads every file beneath one materialisation into a manifest, storing each one as it goes.
///
/// The outer `Result` is a failure of this host; the inner one names something that makes the
/// tested source indeterminate rather than merely different.
#[allow(clippy::too_many_arguments)]
fn walk(
    service: &ChangeSetService,
    directory: &AuthorisedDirectory,
    prefix: &str,
    original: &Manifest,
    grant: &kr_protocol::changeset::FileGrant,
    found: &mut Manifest,
    budget: &mut Budget,
    observed: &mut Vec<ObservedPath>,
    depth: usize,
) -> Result<std::result::Result<(), String>> {
    if depth >= crate::capture::MAX_WALK_DEPTH {
        return Ok(Err(format!(
            "this materialisation is more than {} levels deep, which is deeper than this host \
             reads",
            crate::capture::MAX_WALK_DEPTH
        )));
    }
    let entries = match directory.handle().entries() {
        Ok(entries) => entries,
        Err(error) => {
            return Ok(Err(format!("a directory could not be listed: {error}")));
        }
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return Ok(Err("a directory entry could not be read".to_owned()));
        };
        let Ok(component) = entry.file_name().into_string() else {
            return Ok(Err(
                "a name beneath this materialisation is not readable as text".to_owned(),
            ));
        };
        let path = if prefix.is_empty() {
            component.clone()
        } else {
            format!("{prefix}/{component}")
        };
        let Ok(name) = RelativeName::parse(&component) else {
            return Ok(Err(format!(
                "a name beneath this materialisation is one this host cannot carry: {}",
                kr_project::git::redact(&component)
            )));
        };
        // What kind of thing it is is decided **before** the grant, so an unsupported object at a
        // name a rule would have kept out is still seen. A version that left it out quietly would
        // say the run used a tree that did not hold it.
        let kind = match directory.probe(&name) {
            Ok(kind) => kind,
            Err(error) => {
                return Ok(Err(format!("a name could not be examined: {error}")));
            }
        };
        if !matches!(kind, ObjectKind::Directory | ObjectKind::File) {
            return Ok(Err(format!(
                "this materialisation holds {} at {}, which this host cannot represent in a \
                 version, so what was tested cannot be established",
                match kind {
                    ObjectKind::Link => "a link",
                    _ => "something that is not file content",
                },
                kr_project::git::redact(&path)
            )));
        }
        if budget.entries == 0 {
            return Ok(Err(format!(
                "this materialisation holds more than {} entries, which is more than this host \
                 reads back",
                crate::capture::MAX_WALK_ENTRIES
            )));
        }
        budget.entries -= 1;
        if kind == ObjectKind::Directory {
            if !crate::grant::may_traverse(grant, &path) {
                // A directory a rule keeps out is one a capture of this change set would not have
                // read either, and something under it is an input this host cannot account for.
                return Ok(Err(format!(
                    "this materialisation holds {}, which a capture of this change set would not \
                     read, so what was tested cannot be established",
                    kr_project::git::redact(&path)
                )));
            }
            let Ok(child) = directory.subdirectory(&name) else {
                return Ok(Err(format!(
                    "a directory beneath this materialisation could not be opened: {}",
                    kr_project::git::redact(&path)
                )));
            };
            if let Err(detail) = walk(
                service,
                &child,
                &path,
                original,
                grant,
                found,
                budget,
                observed,
                depth + 1,
            )? {
                return Ok(Err(detail));
            }
            continue;
        }
        // A file a rule keeps out is a source input this host may not read and may not store, and
        // one that is there is an input a result cannot account for.
        if let GrantDecision::Refused(_) = grant::decide(grant, &path) {
            return Ok(Err(format!(
                "this materialisation holds {}, which a capture of this change set would not \
                 read, so what was tested cannot be established",
                kr_project::git::redact(&path)
            )));
        }
        let mut file = match directory.open_read(&name, ObjectPolicy::ReadableFile) {
            Ok(file) => file,
            Err(error) => {
                return Ok(Err(format!("a file could not be opened: {error}")));
            }
        };
        let identity = file.identity();
        let before_len = file.byte_len();
        let before_written = written_at(&file);
        let executable = is_executable(&file);
        let mut bytes = Vec::new();
        let mut bounded = file
            .handle_mut()
            .take(crate::capture::MAX_CAPTURE_FILE_BYTES + 1);
        if let Err(error) = bounded.read_to_end(&mut bytes) {
            return Ok(Err(format!("a file could not be read: {error}")));
        }
        if bytes.len() as u64 > crate::capture::MAX_CAPTURE_FILE_BYTES {
            return Ok(Err(format!(
                "a file beneath this materialisation is larger than the {} bytes this host reads",
                crate::capture::MAX_CAPTURE_FILE_BYTES
            )));
        }
        // The same open handle is asked again, so a file that changed while this host was reading
        // it makes the source indeterminate rather than producing a mixed reading.
        match file.revalidate() {
            Ok(after_len)
                if file.identity() == identity
                    && after_len == before_len
                    && after_len == bytes.len() as u64
                    && written_at(&file) == before_written => {}
            Ok(_) => {
                return Ok(Err(format!(
                    "{} changed while this host was reading it, so what was tested cannot be \
                     established",
                    kr_project::git::redact(&path)
                )));
            }
            Err(error) => {
                return Ok(Err(format!("a file could not be read back: {error}")));
            }
        }
        budget.bytes = match budget.bytes.checked_sub(bytes.len() as u64) {
            Some(left) => left,
            None => {
                return Ok(Err(format!(
                    "this materialisation holds more than {} bytes, which is more than this host \
                     reads back",
                    kr_protocol::changeset::MAX_CAPTURE_BYTES
                )));
            }
        };
        let previous = original.path(&path);
        // Stored from the one reading this walk made, so the digest, the length, the content class
        // and the mode all describe the same bytes.
        let digest = service.objects().put(&bytes)?;
        observed.push(ObservedPath {
            path: path.clone(),
            device: U64::new(identity.device),
            file_id: U64::new(identity.file_id),
            byte_len: U64::new(bytes.len() as u64),
            written_at_nanos: Nullable(before_written.map(U64::new)),
        });
        found.paths.push(CapturedPath {
            content_digest: digest,
            byte_len: U64::new(bytes.len() as u64),
            executable,
            content: crate::capture::classify_content(&bytes),
            origin: ContentOrigin::WorkingTree,
            // The class is recomputed against the input version: a path whose content **or mode**
            // differs is a change of this derived version, one that matches both keeps what it
            // was, and one the run added is untracked.
            class: match previous {
                Some(entry) if entry.content_digest == digest && entry.executable == executable => {
                    entry.class
                }
                Some(_) => PathClass::DirtyFile,
                None => PathClass::UntrackedFile,
            },
            change: ChangeKind::Present,
            base_object_id: previous.map_or(Nullable(None), |entry| entry.base_object_id.clone()),
            base_mode: previous.map_or(Nullable(None), |entry| entry.base_mode.clone()),
            path,
        });
    }
    // A path the version held that the run removed is a deletion of the derived version, named
    // rather than silently absent, and the input version's own exclusions that still apply are
    // carried forward so a reader of the derived version sees the same rules.
    if prefix.is_empty() {
        let here: std::collections::BTreeSet<&str> = found
            .paths
            .iter()
            .map(|entry| entry.path.as_str())
            .collect();
        for entry in &original.paths {
            if !here.contains(entry.path.as_str()) {
                found.deletions.push(crate::version::DeletedPath {
                    path: entry.path.clone(),
                    base_object_id: entry.base_object_id.0.clone(),
                    base_mode: entry.base_mode.0.clone(),
                    // This host reads a directory here, not a repository, so it has nothing to
                    // read the base object out of. The object identifier and its mode travel with
                    // the deletion, and a revert of this derived version reads the object from
                    // the destination's own repository or refuses.
                    content_digest: None,
                });
            }
        }
        // Every exclusion the input version carries that is still true of this reading: the rules
        // a caller cannot select past were applied here too, and a path neither tree holds is
        // still one neither tree holds.
        for exclusion in &original.exclusions {
            if !here.contains(exclusion.path.as_str()) {
                found.exclusions.push(exclusion.clone());
            }
        }
        // And the deletions, with what the base holds for each, so a derived version can be
        // reverted exactly as the version it came from can. A path the run put back is not one of
        // them any more.
        for deleted in &original.deletions {
            if !here.contains(deleted.path.as_str()) {
                found.deletions.push(deleted.clone());
            }
        }
    }
    Ok(Ok(()))
}

/// Returns true when a materialised file is executable.
#[cfg(unix)]
fn is_executable(file: &kr_transfer::AuthorisedFile) -> bool {
    use cap_std::fs::PermissionsExt as _;
    file.handle()
        .metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Returns false: this platform has no executable bit on a file.
#[cfg(not(unix))]
fn is_executable(_file: &kr_transfer::AuthorisedFile) -> bool {
    false
}

/// What a caller says about one run against one materialisation.
#[derive(Clone, Debug)]
pub struct RunReport {
    /// The command that was executed.
    pub command: String,
    /// The profile it was executed under.
    pub profile: String,
    /// Which tool produced it.
    pub tool: ToolIdentity,
    /// What the execution did.
    pub receipt: ExecutionReceipt,
    /// What it produced.
    pub outputs: Vec<OutputReference>,
}

/// Records one result against one materialisation, after establishing what was tested.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownMaterialisation`] when there is no such materialisation.
pub fn record_result(
    service: &ChangeSetService,
    materialisation_id: MaterialisationId,
    report: &RunReport,
) -> Result<MaterialisationResult> {
    let (row, state, observed) = reread(service, materialisation_id)?;
    let input_version = VersionRef {
        change_set_id: row.change_set_id,
        version: row.version,
    };
    let record = service.record(row.change_set_id, Some(row.version))?;
    // Evidence this host can check against the caller's own report: a file written after the run
    // ended is a file the run did not use, so a result about it would be about something else.
    let written_after =
        latest_write(&observed).is_some_and(|written| written > report.receipt.ended_at_ms.get());
    let (tested_source, tested_version, derived, attestation) = match state {
        _ if written_after => (
            TestedSource::Indeterminate,
            None,
            None,
            "something wrote into this materialisation after the run the caller reported had \
             ended, so this host cannot establish what the run read and this result attests no \
             version"
                .to_owned(),
        ),
        Reread::Unmodified => (
            TestedSource::UnmodifiedVersion,
            Some(input_version),
            None,
            "this materialisation still held exactly the version that was written into it: the \
             same paths, the same content, the same modes, and every file still the object this \
             host wrote, of the same length, last written at the same instant. What this host \
             read is the directory at two instants, when it was made and now; it did not watch it \
             while the run was happening, so a run that restored the object, the length and the \
             instant together is not something it would show"
                .to_owned(),
        ),
        Reread::Modified(found) => {
            let derived = derive_from(service, &record, &found, materialisation_id)?;
            (
                // What the directory holds now is not what the run read: a run that changed a
                // file, tested the change and put the file back would be attested against a
                // version it never used. So the source is indeterminate and the reading is
                // recorded beside it as a derived output version, which is what section 14 asks
                // for when a materialisation is modified.
                TestedSource::Indeterminate,
                None,
                Some(VersionRef {
                    change_set_id: derived.change_set_id,
                    version: derived.version,
                }),
                format!(
                    "this materialisation was changed while it was in use, so this result attests \
                     no version at all: it says nothing about version {}, and it does not say \
                     that version {} is what the run read either. Version {} is what the \
                     directory held when the result was recorded, read and stored then, and \
                     establishing which of them a command actually read needs a host that owns \
                     the execution",
                    row.version.get(),
                    derived.version.get(),
                    derived.version.get()
                ),
            )
        }
        Reread::Indeterminate(detail) => (
            TestedSource::Indeterminate,
            None,
            None,
            format!(
                "this host could not establish what was tested, so this result attests no \
                 version: {detail}"
            ),
        ),
    };
    let result = MaterialisationResult {
        materialisation_id,
        input_version,
        tested_source,
        tested_version: Nullable(tested_version),
        derived_output_version: Nullable(derived),
        command: report.command.clone(),
        profile: report.profile.clone(),
        environment_id: service.environment_id(),
        tool: report.tool.clone(),
        receipt: report.receipt.clone(),
        outputs: report.outputs.clone(),
        attestation,
        recorded_at_ms: kr_ipc::now_ms(),
    };
    service.locked()?.insert_result(&ResultRow {
        materialisation_id,
        input_change_set_id: input_version.change_set_id,
        input_version: input_version.version,
        tested_source,
        tested_version: tested_version
            .map(|reference| (reference.change_set_id, reference.version)),
        derived_output_version: derived
            .map(|reference| (reference.change_set_id, reference.version)),
        record: encode_stored(&result)?,
        recorded_at_ms: result.recorded_at_ms,
    })?;
    Ok(result)
}

/// Returns the latest instant anything beneath one materialisation was written, in milliseconds.
///
/// Read from the observations the re-read itself made, which are the same objects it read. A
/// platform that reports no instant contributes nothing, and the rule that uses this then decides
/// nothing either, which is said where the limit is stated.
fn latest_write(observed: &[ObservedPath]) -> Option<u64> {
    observed
        .iter()
        .filter_map(|observed| {
            observed
                .written_at_nanos
                .0
                .map(|value| value.get() / 1_000_000)
        })
        .max()
}

/// Records the version a changed materialisation actually held.
///
/// The manifest is the one the walk built, whose every byte it already put in the content store,
/// so nothing is read a second time and no field can come to describe different bytes from the
/// digest beside it.
fn derive_from(
    service: &ChangeSetService,
    from: &ChangeSetVersionRecord,
    found: &Manifest,
    materialisation_id: MaterialisationId,
) -> Result<ChangeSetVersionRecord> {
    let provenance = Provenance {
        actor_id: from.provenance.actor_id.clone(),
        method: "changeset.materialize".to_owned(),
        session_id: from.provenance.session_id,
        workflow_run_id: from.provenance.workflow_run_id,
        derived_from: Nullable(Some(VersionRef {
            change_set_id: from.change_set_id,
            version: from.version,
        })),
        derivation: format!(
            "materialisation {materialisation_id} was changed while it was in use, and this is \
             what it held"
        ),
        note: String::new(),
    };
    service.derive(
        from,
        found,
        provenance,
        // Read file by file from a live directory, whatever the input version's own class was: a
        // version's consistency is a fact about how **it** was read.
        SourceConsistency::PerFileCapture,
        "this version was read from a materialisation, one file at a time, rather than from a \
         working tree or a commit; it is a record of what that directory held when the result was \
         recorded"
            .to_owned(),
    )
}

/// Takes one materialisation's directory away and records that it is released.
///
/// Until this is called the materialisation is something a deletion of its version has to account
/// for, which is what [`ChangeSetService::holders`] reports.
///
/// The removal goes **through the handle** this host opened and checked the identity of: every
/// level is listed and emptied through its own open directory, and each name is taken away by the
/// parent that holds it. A directory somebody substituted at the materialisation's own name is
/// therefore not reached at all, rather than being emptied by a removal that resolved the name a
/// second time. A removal this host could not finish is a failure: the materialisation goes on
/// holding its version rather than losing that protection without its contents being gone.
///
/// What this does remove is **everything beneath that verified root**, including whatever the run
/// put there, because that is what releasing a materialisation means: the directory is one this
/// host made for one run and the run's output lives in it. It does not check each descendant
/// against a record of what this host wrote, so a directory a same-account writer substituted
/// *inside* the materialisation goes with it. That writer could have emptied it themselves; the
/// stronger rule that D-057(b) puts on the profile's own temporary directories is for a case where
/// this host cannot say it created the directory at all, and here it can.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownMaterialisation`] when there is no such materialisation, and
/// [`ChangeSetError::StorageUnavailable`] when the directory could not be taken away.
pub fn release(
    service: &ChangeSetService,
    materialisation_id: MaterialisationId,
) -> Result<MaterialisationRecord> {
    let row = service
        .locked()?
        .materialisation(materialisation_id)?
        .ok_or_else(|| ChangeSetError::UnknownMaterialisation {
            detail: format!("no materialisation {materialisation_id}").into(),
        })?;
    let parent = service
        .root()
        .subdirectory(&RelativeName::parse(MATERIALISATIONS_DIRECTORY)?)?;
    let name = RelativeName::parse(&row.directory_name)?;
    match parent.subdirectory(&name) {
        Ok(directory) => {
            if directory.identity() != row.identity {
                return Err(ChangeSetError::StorageUnavailable {
                    detail: "the directory at this materialisation's name is not the object this \
                             host made, so nothing was removed and nothing is recorded as released"
                        .into(),
                });
            }
            empty(&directory, 0)?;
            // The name goes last, and only as an empty-directory removal, which takes nothing that
            // holds anything. What is left is the limit every removal by name has: an empty
            // directory somebody put there in the instant after the check.
            parent
                .handle()
                .remove_dir(name.as_str())
                .map_err(ChangeSetError::storage)?;
            parent.sync()?;
        }
        // A plain absence is a release that already happened. Anything else is a failure: this
        // host does not record a release it could not establish.
        Err(kr_transfer::Escape::NotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }
    let mut record: MaterialisationRecord = decode_stored(&row.record)?;
    let now = kr_ipc::now_ms();
    record.released_at_ms = Nullable(Some(now));
    service
        .locked()?
        .release_materialisation(materialisation_id, &encode_stored(&record)?, now)?;
    Ok(record)
}

/// Empties one directory through its own open handle.
///
/// Nothing here resolves a name a second time: each level is opened from the level above, and each
/// entry is removed by the handle that holds it.
fn empty(directory: &AuthorisedDirectory, depth: usize) -> Result<()> {
    if depth >= crate::capture::MAX_WALK_DEPTH {
        return Err(ChangeSetError::StorageUnavailable {
            detail: format!(
                "this materialisation is more than {} levels deep, which is deeper than this host \
                 removes",
                crate::capture::MAX_WALK_DEPTH
            )
            .into(),
        });
    }
    let names: Vec<String> = directory
        .handle()
        .entries()
        .map_err(ChangeSetError::storage)?
        .map(|entry| {
            entry
                .map_err(ChangeSetError::storage)?
                .file_name()
                .into_string()
                .map_err(|_| ChangeSetError::StorageUnavailable {
                    detail: "this materialisation holds a name this host cannot read as text"
                        .into(),
                })
        })
        .collect::<Result<Vec<String>>>()?;
    for component in names {
        let name = RelativeName::parse(&component)?;
        match directory.probe(&name) {
            Ok(ObjectKind::Directory) => {
                let child = directory.subdirectory(&name)?;
                empty(&child, depth + 1)?;
                directory
                    .handle()
                    .remove_dir(name.as_str())
                    .map_err(ChangeSetError::storage)?;
            }
            // A file, a link or anything else that is not a directory is one entry of the
            // directory this host holds open, removed by the handle that holds it.
            Ok(_) => directory.remove(&name)?,
            Err(kr_transfer::Escape::NotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Returns every materialisation of one version that still holds it.
///
/// # Errors
///
/// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
pub fn outstanding(
    service: &ChangeSetService,
    version: VersionRef,
) -> Result<Vec<MaterialisationRecord>> {
    let rows = service
        .locked()?
        .materialisations(version.change_set_id, version.version, false)?;
    rows.iter().map(|row| decode_stored(&row.record)).collect()
}

/// Returns every materialisation of one version, released or not.
///
/// # Errors
///
/// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
pub fn every(
    service: &ChangeSetService,
    change_set_id: kr_protocol::ids::ChangeSetId,
    version: ChangeSetVersion,
) -> Result<Vec<MaterialisationRecord>> {
    let rows = service
        .locked()?
        .materialisations(change_set_id, version, true)?;
    rows.iter().map(|row| decode_stored(&row.record)).collect()
}

/// Returns every result recorded against one version's materialisations.
///
/// # Errors
///
/// Returns [`ChangeSetError::StoreUnavailable`] when the read fails.
pub fn results(
    service: &ChangeSetService,
    change_set_id: kr_protocol::ids::ChangeSetId,
    version: ChangeSetVersion,
) -> Result<Vec<MaterialisationResult>> {
    let rows = service.locked()?.results(change_set_id, version)?;
    rows.iter().map(|row| decode_stored(&row.record)).collect()
}
