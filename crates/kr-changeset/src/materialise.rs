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
//! * unreadable — the result says [`TestedSource::Indeterminate`] and attests nothing.
//!
//! Every one of the three is recorded as evidence against the version it names, so retention
//! accounts for it before anything is deleted.

use std::io::{Read as _, Write as _};

use kr_protocol::changeset::{
    CapturedPath, ChangeSetVersionRecord, ContentOrigin, ExecutionReceipt, MaterialisationPurpose,
    MaterialisationRecord, MaterialisationResult, OutputReference, PathClass, Provenance,
    TestedSource, ToolIdentity, VersionRef,
};
use kr_protocol::ids::{ChangeSetVersion, MaterialisationId};
use kr_protocol::project::{ChangeKind, ContentClass, FilesystemIdentity};
use kr_protocol::scalars::{Nullable, U64};
use kr_transfer::authority::ObjectKind;
use kr_transfer::{AuthorisedDirectory, ObjectPolicy, RelativeName};

use crate::error::{ChangeSetError, Result};
use crate::objects::digest_of;
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
    let directory = parent.create_subdirectory(&name)?;
    let mut written = 0_u64;
    let mut unapplied = Vec::new();
    for entry in &manifest.paths {
        match write_path(service, &directory, entry) {
            Ok(()) => written += 1,
            Err(_) => unapplied.push(entry.path.clone()),
        }
    }
    directory.sync()?;
    let identity = directory.identity();
    let record = MaterialisationRecord {
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
        paths_written: U64::new(written),
        unapplied,
        created_at_ms: kr_ipc::now_ms(),
        released_at_ms: Nullable(None),
    };
    service
        .locked()?
        .insert_materialisation(&MaterialisationRow {
            materialisation_id,
            change_set_id: version.change_set_id,
            version: version.version,
            purpose,
            record: encode_stored(&record)?,
            directory_name,
            identity,
            created_at_ms: record.created_at_ms,
            released_at_ms: None,
        })?;
    Ok(record)
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
) -> Result<()> {
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
    Ok(())
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
    /// The directory held exactly the version.
    Unmodified,
    /// It held something else, and this is what.
    Modified(Manifest),
    /// This host could not establish what it held.
    Indeterminate(String),
}

/// Re-reads one materialisation and says whether it still holds the version.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownMaterialisation`] when there is no such materialisation.
pub fn reread(
    service: &ChangeSetService,
    materialisation_id: MaterialisationId,
) -> Result<(MaterialisationRow, Reread)> {
    let row = service
        .locked()?
        .materialisation(materialisation_id)?
        .ok_or_else(|| ChangeSetError::UnknownMaterialisation {
            detail: format!("no materialisation {materialisation_id}").into(),
        })?;
    let original = service.manifest(row.change_set_id, row.version)?;
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
        ));
    }
    let mut found = Manifest {
        paths: Vec::new(),
        exclusions: Vec::new(),
    };
    if let Err(detail) = walk(&directory, "", &original, &mut found) {
        return Ok((row, Reread::Indeterminate(detail)));
    }
    found.canonicalise();
    if same_content(&original, &found) {
        Ok((row, Reread::Unmodified))
    } else {
        Ok((row, Reread::Modified(found)))
    }
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

/// Reads every file beneath one materialisation into a manifest.
fn walk(
    directory: &AuthorisedDirectory,
    prefix: &str,
    original: &Manifest,
    found: &mut Manifest,
) -> std::result::Result<(), String> {
    let entries = directory
        .handle()
        .entries()
        .map_err(|error| format!("a directory could not be listed: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("a directory entry could not be read: {error}"))?;
        let component = entry.file_name().into_string().map_err(|_| {
            "a name beneath this materialisation is not readable as text".to_owned()
        })?;
        let path = if prefix.is_empty() {
            component.clone()
        } else {
            format!("{prefix}/{component}")
        };
        let name = RelativeName::parse(&component)
            .map_err(|error| format!("a name beneath this materialisation is refused: {error}"))?;
        match directory.probe(&name) {
            Ok(ObjectKind::Directory) => {
                let child = directory
                    .subdirectory(&name)
                    .map_err(|error| format!("a directory could not be opened: {error}"))?;
                walk(&child, &path, original, found)?;
            }
            Ok(ObjectKind::File) => {
                let mut file = directory
                    .open_read(&name, ObjectPolicy::ReadableFile)
                    .map_err(|error| format!("a file could not be opened: {error}"))?;
                let mut bytes = Vec::new();
                file.handle_mut()
                    .read_to_end(&mut bytes)
                    .map_err(|error| format!("a file could not be read: {error}"))?;
                let executable = is_executable(&file);
                let previous = original.path(&path);
                found.paths.push(CapturedPath {
                    content_digest: digest_of(&bytes),
                    byte_len: U64::new(bytes.len() as u64),
                    executable,
                    content: if bytes
                        .iter()
                        .take(kr_project::workspace::BINARY_SCAN_BYTES)
                        .any(|byte| *byte == 0)
                    {
                        ContentClass::Binary
                    } else {
                        ContentClass::Text
                    },
                    origin: ContentOrigin::WorkingTree,
                    // A path the version held keeps its class; one the run added is an untracked
                    // file of the derived version, because that is exactly what it is.
                    class: previous.map_or(PathClass::UntrackedFile, |entry| entry.class),
                    change: ChangeKind::Present,
                    base_object_id: previous
                        .map_or(Nullable(None), |entry| entry.base_object_id.clone()),
                    path,
                });
            }
            // A link or a device inside a materialisation is something the run put there, and it
            // is not content this host reads. The derived version says so by leaving it out, and
            // the difference from the input version is what makes the result a derived one.
            Ok(_) => {}
            Err(error) => {
                return Err(format!("a name could not be examined: {error}"));
            }
        }
    }
    Ok(())
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
    let (row, state) = reread(service, materialisation_id)?;
    let input_version = VersionRef {
        change_set_id: row.change_set_id,
        version: row.version,
    };
    let record = service.record(row.change_set_id, Some(row.version))?;
    let (tested_source, tested_version, attestation) = match state {
        Reread::Unmodified => (
            TestedSource::UnmodifiedVersion,
            Some(input_version),
            "this materialisation still held exactly the version that was written into it when \
             the result was recorded, so the result is about that version"
                .to_owned(),
        ),
        Reread::Modified(found) => {
            let derived = derive_from(service, &record, &found, materialisation_id)?;
            (
                TestedSource::DerivedVersion,
                Some(VersionRef {
                    change_set_id: derived.change_set_id,
                    version: derived.version,
                }),
                format!(
                    "this materialisation was changed while it was in use, so this result is \
                     about version {} of the change set, which this host recorded from what the \
                     directory actually held; it says nothing about version {}",
                    derived.version.get(),
                    row.version.get()
                ),
            )
        }
        Reread::Indeterminate(detail) => (
            TestedSource::Indeterminate,
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
        tested_source,
        tested_version: tested_version
            .map(|reference| (reference.change_set_id, reference.version)),
        record: encode_stored(&result)?,
        recorded_at_ms: result.recorded_at_ms,
    })?;
    Ok(result)
}

/// Records the version a changed materialisation actually held.
fn derive_from(
    service: &ChangeSetService,
    from: &ChangeSetVersionRecord,
    found: &Manifest,
    materialisation_id: MaterialisationId,
) -> Result<ChangeSetVersionRecord> {
    // Every byte the run left behind goes into the content store, so the derived version names
    // content this host holds rather than content that is only in a directory somebody may remove.
    let mut stored = found.clone();
    for entry in &mut stored.paths {
        let bytes = read_materialised(service, materialisation_id, &entry.path)?;
        entry.content_digest = service.objects().put(&bytes)?;
    }
    stored.canonicalise();
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
        &stored,
        provenance,
        "this version was read from a materialisation rather than from a working tree, so it is a \
         record of what was tested rather than of one instant of anybody's tree"
            .to_owned(),
    )
}

/// Reads one path out of one materialisation.
fn read_materialised(
    service: &ChangeSetService,
    materialisation_id: MaterialisationId,
    path: &str,
) -> Result<Vec<u8>> {
    let row = service
        .locked()?
        .materialisation(materialisation_id)?
        .ok_or_else(|| ChangeSetError::UnknownMaterialisation {
            detail: format!("no materialisation {materialisation_id}").into(),
        })?;
    let parent = service
        .root()
        .subdirectory(&RelativeName::parse(MATERIALISATIONS_DIRECTORY)?)?;
    let directory = parent.subdirectory(&RelativeName::parse(&row.directory_name)?)?;
    let mut file = directory.open_read(&RelativeName::parse(path)?, ObjectPolicy::ReadableFile)?;
    let mut bytes = Vec::new();
    file.handle_mut()
        .read_to_end(&mut bytes)
        .map_err(ChangeSetError::storage)?;
    Ok(bytes)
}

/// Takes one materialisation's directory away and records that it is released.
///
/// Until this is called the materialisation is something a deletion of its version has to account
/// for, which is what [`ChangeSetService::holders`] reports.
///
/// # Errors
///
/// Returns [`ChangeSetError::UnknownMaterialisation`] when there is no such materialisation.
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
        Ok(directory) if directory.identity() == row.identity => {
            // Inside this service's own directory, which is the account's own at mode 0700, and
            // named by an identifier this host generated and recorded with the object's identity.
            // What is left is an empty directory somebody put at the name in the instant between
            // the check and the removal, which is the same limit every removal by name has.
            parent
                .handle()
                .remove_dir_all(name.as_str())
                .map_err(ChangeSetError::storage)?;
        }
        // Absent, or not the object this host made. Either way nothing is removed: this host does
        // not delete a directory it cannot prove it created.
        _ => {}
    }
    let mut record: MaterialisationRecord = decode_stored(&row.record)?;
    let now = kr_ipc::now_ms();
    record.released_at_ms = Nullable(Some(now));
    service
        .locked()?
        .release_materialisation(materialisation_id, &encode_stored(&record)?, now)?;
    Ok(record)
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
