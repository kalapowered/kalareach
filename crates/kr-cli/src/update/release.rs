//! What makes a release one this host installs, and putting one into the store.
//!
//! A release is taken in only whole and checked, in this order: its files are written where
//! nothing runs them, under the store's `staging/`, each read once and its digest taken as it is
//! written; its manifest is checked against the update channel's root, a threshold of the release
//! keys that root names having signed it; every file it lists is there with its length and digest,
//! and nothing it does not list is; it is for this system; and only then is it made read-only,
//! flushed, and renamed into `versions/` in one step. Nothing a release carries is trusted before
//! its manifest is, and nothing of it is used until it is all there.
//!
//! An archive is refused at the first entry that could put something outside the release or be
//! something other than a file: a link, a device, a path that is absolute or climbs out of the
//! archive's one top directory. What the archive says about a file's mode or owner is not read:
//! a file is a program when the manifest says it is.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::scalars::Digest256;
use kr_protocol::update::{
    FileMode, FloorSystem, FloorVersion, MANIFEST_FILE, MAX_MANIFEST_LEN, ReleaseManifest,
};
use sha2::Digest as _;

use crate::error::{CliError, Result};

/// Where a release keeps the update channel's root, relative to its directory.
pub const CHANNEL_ROOT: &str = "share/update-root.json";

/// The largest channel root this host reads.
const MAX_ROOT_LEN: u64 = 1024 * 1024;

/// What is left free on a filesystem a release is written to, beyond the release itself.
const SPACE_MARGIN: u64 = 64 * 1024 * 1024;

/// The target this build is for, as a release's manifest names it.
#[must_use]
pub const fn this_target() -> &'static str {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu"
    )) {
        "aarch64-unknown-linux-gnu"
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_env = "gnu"
    )) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_arch = "aarch64", target_os = "windows")) {
        "aarch64-pc-windows-msvc"
    } else if cfg!(all(target_arch = "x86_64", target_os = "windows")) {
        "x86_64-pc-windows-msvc"
    } else {
        "unsupported"
    }
}

/// A release manifest as the release keys sign it: the manifest's own JSON, whole, members this
/// build does not know included, so what is checked is exactly what was signed.
///
/// It is checked as The Update Framework checks a targets role: over its canonical JSON, by a
/// threshold of the keys the channel root names for that role. The manifest's own `_type` is part
/// of what is signed, which keeps a signature over the channel's targets metadata from passing for
/// one over a release.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Signable(pub kr_protocol::update::SignedMembers);

impl tough::schema::Role for Signable {
    const TYPE: tough::schema::RoleType = tough::schema::RoleType::Targets;

    /// A release does not expire: what it is stays what it was signed as.
    fn expires(&self) -> jiff::Timestamp {
        jiff::Timestamp::MAX
    }

    fn version(&self) -> NonZeroU64 {
        NonZeroU64::MIN
    }

    fn filename(&self, _consistent_snapshot: bool) -> String {
        MANIFEST_FILE.to_owned()
    }
}

/// The update channel's root a release carries: The Update Framework's root metadata, which names
/// the keys of each role and how many of each must sign.
pub struct ChannelRoot {
    signed: tough::schema::Signed<tough::schema::Root>,
}

impl ChannelRoot {
    /// Reads the root a release directory carries, and checks it against itself: a threshold of the
    /// root keys it names signed it. `None` when the release carries no root.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the root cannot be read, is not root metadata, or is not signed by
    /// its own root keys.
    pub fn read(release: &Path) -> Result<Option<Self>> {
        let path = release.join(CHANNEL_ROOT);
        let bytes = match read_bounded(&path, MAX_ROOT_LEN) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(CliError::Other(shown!(
                    "the update channel's root at {} could not be read: {}",
                    Shown::root(&path),
                    Shown::io(&error)
                )));
            }
        };
        let signed: tough::schema::Signed<tough::schema::Root> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                CliError::Other(shown!(
                    "the update channel's root at {} is not root metadata: {}",
                    Shown::root(&path),
                    Shown::json(&error)
                ))
            })?;
        signed.signed.verify_role(&signed).map_err(|_| {
            CliError::Other(shown!(
                "the update channel's root at {} is not signed by the root keys it names",
                Shown::root(&path)
            ))
        })?;
        Ok(Some(Self { signed }))
    }

    /// Checks that `next`, the root a release carries, is this root or the one that follows it:
    /// the next version, signed by a threshold of this root's root keys as well as its own.
    ///
    /// # Errors
    ///
    /// Returns a refusal naming what does not follow.
    pub fn admits_successor(&self, next: &Self) -> Result<()> {
        if next.signed == self.signed {
            return Ok(());
        }
        let this_version = self.signed.signed.version.get();
        let next_version = next.signed.signed.version.get();
        if next_version != this_version.saturating_add(1) {
            return Err(CliError::Other(shown!(
                "the release carries update channel root version {}, and this host trusts version \
                 {}: a release carries this host's root or the one that follows it",
                next_version,
                this_version
            )));
        }
        self.signed.signed.verify_role(&next.signed).map_err(|_| {
            CliError::Other(Shown::said(
                "the release's update channel root is not signed by the root keys this host \
                 trusts",
            ))
        })
    }

    /// Reads a release's `release.json` and checks it: a threshold of the keys this root names for
    /// its targets role signed the manifest, and the manifest lists files a host can install.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the document is not a signed manifest, or its signatures do not
    /// reach the threshold.
    pub fn verify(&self, document: &[u8]) -> Result<ReleaseManifest> {
        let signed: tough::schema::Signed<Signable> =
            serde_json::from_slice(document).map_err(|error| {
                CliError::Other(shown!(
                    "the release's manifest is not a signed document: {}",
                    Shown::json(&error)
                ))
            })?;
        self.signed.signed.verify_role(&signed).map_err(|_| {
            CliError::Other(Shown::said(
                "the release's manifest is not signed by the release keys the update channel's \
                 root names",
            ))
        })?;
        signed.signed.0.manifest().map_err(|_| {
            CliError::Other(Shown::said(
                "the release's manifest is not one this build reads, or lists files a host \
                 cannot install",
            ))
        })
    }
}

/// Reads a manifest document without its signatures: what a first installation, which has no
/// root yet to check it against, takes a release's own word for.
///
/// # Errors
///
/// Returns a refusal when the document is not a release manifest.
pub fn read_manifest(document: &[u8]) -> Result<ReleaseManifest> {
    ReleaseManifest::read_document(document).map_err(|_| {
        CliError::Other(Shown::said(
            "the release's manifest is not one this build reads, or lists files a host cannot \
             install",
        ))
    })
}

/// Reads a file whole, refusing one longer than `limit`.
fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other(
            "the file is larger than any this host reads here",
        ));
    }
    Ok(bytes)
}

/// Checks that this host runs what a release is built for: its target, and an operating system at
/// or above its floor.
///
/// # Errors
///
/// Returns a refusal naming the target or the floor that does not hold.
pub fn check_system(manifest: &ReleaseManifest) -> Result<()> {
    if manifest.target != this_target() {
        return Err(CliError::Other(shown!(
            "the release is built for another system than this host's, which is {}",
            this_target()
        )));
    }
    let floor = manifest.os_floor;
    let needed = shown!("{}.{}", floor.version.major, floor.version.minor);
    match host_version(floor.system) {
        Some(version) if version >= floor.version => Ok(()),
        Some(version) => Err(CliError::Other(shown!(
            "the release needs {} {} or later, and this host has {}.{}",
            floor.system.as_str(),
            needed,
            version.major,
            version.minor
        ))),
        None => Err(CliError::Other(shown!(
            "the release needs {} {} or later, and which this host has could not be read",
            floor.system.as_str(),
            needed
        ))),
    }
}

/// This host's version of what a floor is a version of, where it can be read.
fn host_version(system: FloorSystem) -> Option<FloorVersion> {
    let (program, arguments): (&str, &[&str]) = match system {
        FloorSystem::Macos if cfg!(target_os = "macos") => {
            ("/usr/bin/sw_vers", &["-productVersion"])
        }
        // `glibc 2.35`: the second word is the version.
        FloorSystem::Glibc if cfg!(target_os = "linux") => ("getconf", &["GNU_LIBC_VERSION"]),
        _ => return None,
    };
    let output = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let version = text.split_whitespace().last()?;
    FloorVersion::leading(version)
}

/// What was written for a release: each file's path relative to the release, its length and its
/// digest, taken as it was written.
pub type Written = BTreeMap<String, (u64, Digest256)>;

/// Unpacks a release archive, `.tar.gz`, into `staging`, an owner-only directory, and returns the
/// release's directory in it and what was written.
///
/// Every entry is under one top directory, which is the release's directory; an entry is a
/// directory or a file and nothing else. The first entry that is anything else, or whose path is
/// absolute, climbs out of the top directory or is not text, refuses the whole archive.
///
/// # Errors
///
/// Returns a refusal naming what is wrong with the archive, or the failure to read or write it.
pub fn unpack(archive: &Path, staging: &Path) -> Result<(PathBuf, Written)> {
    let unreadable = |error: &std::io::Error| {
        CliError::Other(shown!(
            "the archive {} could not be read: {}",
            Shown::root(archive),
            Shown::io(error)
        ))
    };
    let file = std::fs::File::open(archive).map_err(|error| unreadable(&error))?;
    let mut entries =
        tar::Archive::new(flate2::read::GzDecoder::new(std::io::BufReader::new(file)));
    let mut top: Option<String> = None;
    let mut written = Written::new();
    for entry in entries.entries().map_err(|error| unreadable(&error))? {
        let mut entry = entry.map_err(|error| unreadable(&error))?;
        let kind = entry.header().entry_type();
        // A global extension header describes the archive, not a file, and names nothing.
        if kind.is_pax_global_extensions() {
            continue;
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(refused_archive(
                archive,
                "has an entry that is neither a file nor a directory, such as a link or a device",
            ));
        }
        let path = entry.path().map_err(|error| unreadable(&error))?;
        let (entry_top, relative) = split_entry(&path).ok_or_else(|| {
            refused_archive(archive, "has an entry whose path is not a release's")
        })?;
        match &top {
            Some(top) if *top != entry_top => {
                return Err(refused_archive(
                    archive,
                    "has entries under more than one top directory",
                ));
            }
            Some(_) => {}
            None => top = Some(entry_top.clone()),
        }
        let directory = staging.join(&entry_top);
        let destination = relative
            .iter()
            .fold(directory.clone(), |path, part| path.join(part));
        if kind.is_dir() {
            create_directories(staging, &destination)?;
            continue;
        }
        if relative.is_empty() {
            return Err(refused_archive(
                archive,
                "has a file where its top directory goes",
            ));
        }
        if let Some(parent) = destination.parent() {
            create_directories(staging, parent)?;
        }
        ensure_space(staging, entry.size())?;
        let summary = write_new(&destination, &mut entry)
            .map_err(|error| write_failure(&destination, &error))?;
        if written.insert(relative.join("/"), summary).is_some() {
            return Err(refused_archive(archive, "has the same file twice"));
        }
    }
    let top = top.ok_or_else(|| refused_archive(archive, "is empty"))?;
    Ok((staging.join(top), written))
}

/// Copies an unpacked release's tree into `staging`, an owner-only directory, and returns the copy
/// and what was written.
///
/// A file is copied and a directory made; anything else in the tree, a link above all, refuses
/// the tree, since what it points at is not part of what the manifest describes.
///
/// # Errors
///
/// Returns a refusal naming what is wrong with the tree, or the failure to read or write it.
pub fn copy_tree(tree: &Path, staging: &Path) -> Result<(PathBuf, Written)> {
    let copy = staging.join("release");
    create_directories(staging, &copy)?;
    let mut written = Written::new();
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(tree.to_path_buf(), Vec::new())];
    while let Some((directory, relative)) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            CliError::Other(shown!(
                "the release at {} could not be read: {}",
                Shown::root(tree),
                Shown::io(&error)
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                CliError::Other(shown!(
                    "the release at {} could not be read: {}",
                    Shown::root(tree),
                    Shown::io(&error)
                ))
            })?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| refused_tree(tree, "holds a name that is not text"))?;
            let kind = entry.file_type().map_err(|error| {
                CliError::Other(shown!(
                    "the release at {} could not be read: {}",
                    Shown::root(tree),
                    Shown::io(&error)
                ))
            })?;
            let mut path = relative.clone();
            path.push(name);
            let destination = path.iter().fold(copy.clone(), |at, part| at.join(part));
            if kind.is_dir() {
                create_directories(staging, &destination)?;
                pending.push((entry.path(), path));
            } else if kind.is_file() {
                let source = entry.path();
                let mut opened = std::fs::File::open(&source).map_err(|error| {
                    CliError::Other(shown!(
                        "the release at {} could not be read: {}",
                        Shown::root(tree),
                        Shown::io(&error)
                    ))
                })?;
                let length = opened.metadata().map(|about| about.len()).unwrap_or(0);
                ensure_space(staging, length)?;
                let summary = write_new(&destination, &mut opened)
                    .map_err(|error| write_failure(&destination, &error))?;
                written.insert(path.join("/"), summary);
            } else {
                return Err(refused_tree(
                    tree,
                    "holds something that is neither a file nor a directory, such as a link",
                ));
            }
        }
    }
    Ok((copy, written))
}

/// Splits an archive entry's path into its top directory and the parts below it, when it is a
/// relative path of text parts that stays inside that directory.
fn split_entry(path: &Path) -> Option<(String, Vec<String>)> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_owned()),
            // `./release/...` is how some tools write a relative path.
            Component::CurDir if parts.is_empty() => {}
            _ => return None,
        }
    }
    if parts.is_empty() {
        return None;
    }
    let top = parts.remove(0);
    Some((top, parts))
}

/// Creates `directory` and its parents below `staging`, owner-only.
fn create_directories(staging: &Path, directory: &Path) -> Result<()> {
    kr_ipc::paths::create_private_tree(staging, directory).map_err(|error| {
        CliError::Other(shown!(
            "the staging directory {} could not be made: {}",
            Shown::root(directory),
            Shown::ipc(&error)
        ))
    })
}

/// Writes a new file from `source`, owner-only, and returns its length and digest.
fn write_new(
    destination: &Path,
    source: &mut impl std::io::Read,
) -> std::io::Result<(u64, Digest256)> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(kr_ipc::paths::OWNER_ONLY_FILE_MODE)
        .open(destination)?;
    let mut hasher = sha2::Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        file.write_all(&buffer[..read])?;
        length += read as u64;
    }
    file.sync_all()?;
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((length, Digest256::from_bytes(digest)))
}

/// Refuses to write `length` more bytes where that would leave less than [`SPACE_MARGIN`] free.
fn ensure_space(directory: &Path, length: u64) -> Result<()> {
    let free = rustix::fs::statvfs(directory)
        .map(|about| about.f_bavail.saturating_mul(about.f_frsize))
        .map_err(|error| {
            CliError::Other(shown!(
                "the free space at {} could not be read: {}",
                Shown::root(directory),
                Shown::io(&std::io::Error::from(error))
            ))
        })?;
    if free < length.saturating_add(SPACE_MARGIN) {
        return Err(CliError::Other(shown!(
            "the filesystem of {} has {} bytes free, and staging the release needs {} more and \
             {} to spare",
            Shown::root(directory),
            free,
            length,
            SPACE_MARGIN
        )));
    }
    Ok(())
}

/// Checks what was written against the manifest: every file it lists, with its length and digest,
/// and nothing it does not list but the manifest itself.
///
/// # Errors
///
/// Returns a refusal counting the files that differ, are missing or are not listed.
pub fn check_files(manifest: &ReleaseManifest, written: &Written) -> Result<()> {
    let mut listed = std::collections::BTreeSet::new();
    let mut differing = 0_usize;
    let mut missing = 0_usize;
    for file in &manifest.files {
        listed.insert(file.path.as_str());
        match written.get(file.path.as_str()) {
            Some((length, digest)) if *length == file.length.get() && *digest == file.sha256 => {}
            Some(_) => differing += 1,
            None => missing += 1,
        }
    }
    let unlisted = written
        .keys()
        .filter(|path| path.as_str() != MANIFEST_FILE && !listed.contains(path.as_str()))
        .count();
    if differing + missing + unlisted > 0 {
        return Err(CliError::Other(shown!(
            "the release is not what its manifest says: {} of its files differ from it, {} it \
             lists are missing and {} are not listed",
            differing,
            missing,
            unlisted
        )));
    }
    Ok(())
}

/// Reads the manifest a staged release holds, bounded.
///
/// # Errors
///
/// Returns a refusal when the release holds none, or one too large to be one.
pub fn manifest_document(release: &Path) -> Result<Vec<u8>> {
    let path = release.join(MANIFEST_FILE);
    read_bounded(&path, MAX_MANIFEST_LEN).map_err(|error| {
        CliError::Other(shown!(
            "the release has no manifest this host reads at {}: {}",
            Shown::root(&path),
            Shown::io(&error)
        ))
    })
}

/// Makes a staged release read-only, a program runnable as well, as its manifest says, and flushes
/// every file and directory of it.
///
/// The release's own directory is flushed and left writable: it is renamed into `versions/`
/// next, and a directory moves to another parent only while its own entries can be written, on
/// some systems. [`admit`] makes it read-only once it is there.
///
/// # Errors
///
/// Returns the failure to change or flush a file.
pub fn seal(release: &Path, manifest: &ReleaseManifest) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let modes: BTreeMap<&str, FileMode> = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.mode))
        .collect();
    let mut directories = Vec::new();
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(release.to_path_buf(), Vec::new())];
    while let Some((directory, relative)) = pending.pop() {
        directories.push(directory.clone());
        let entries = std::fs::read_dir(&directory).map_err(|error| sealing(&directory, &error))?;
        for entry in entries {
            let entry = entry.map_err(|error| sealing(&directory, &error))?;
            let mut path = relative.clone();
            path.push(entry.file_name().to_string_lossy().into_owned());
            let kind = entry
                .file_type()
                .map_err(|error| sealing(&entry.path(), &error))?;
            if kind.is_dir() {
                pending.push((entry.path(), path));
                continue;
            }
            let mode = match modes.get(path.join("/").as_str()) {
                Some(FileMode::Executable) => 0o555,
                _ => 0o444,
            };
            let file = entry.path();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode))
                .and_then(|()| std::fs::File::open(&file).and_then(|opened| opened.sync_all()))
                .map_err(|error| sealing(&file, &error))?;
        }
    }
    // Deepest first, so a directory is flushed after everything in it and made read-only last.
    for directory in directories.iter().rev() {
        std::fs::File::open(directory)
            .and_then(|opened| opened.sync_all())
            .and_then(|()| {
                if directory == release {
                    Ok(())
                } else {
                    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o555))
                }
            })
            .map_err(|error| sealing(directory, &error))?;
    }
    Ok(())
}

/// Moves a sealed release into the store's `versions/` in one rename, makes its directory
/// read-only, and flushes both directories the rename changed.
///
/// # Errors
///
/// Returns a refusal when a release of that name is already there, and the failure to move or
/// flush otherwise.
pub fn admit(
    staged: &Path,
    store: &kr_ipc::install::Store,
    release: &kr_protocol::update::ReleaseName,
) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let destination = store.release_directory(release);
    if destination.exists() {
        return Err(CliError::Other(shown!(
            "the store already holds release {}",
            crate::shown::release(release)
        )));
    }
    std::fs::rename(staged, &destination).map_err(|error| sealing(&destination, &error))?;
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o555))
        .and_then(|()| std::fs::File::open(store.versions()).and_then(|opened| opened.sync_all()))
        .and_then(|()| {
            staged.parent().map_or(Ok(()), |parent| {
                std::fs::File::open(parent).and_then(|opened| opened.sync_all())
            })
        })
        .map_err(|error| sealing(&destination, &error))?;
    Ok(destination)
}

/// Checks a release already in the store's `versions/` as a staged release is checked, and seals
/// it as [`admit`] leaves one: what an install or an update that stopped after putting it there
/// left, used again only once it is whole.
///
/// Every file it holds is read again and its digest taken; it holds files and directories only,
/// every file its manifest lists with its length and digest, and nothing else but the manifest.
/// Its manifest is the caller's to compare with the one just checked.
///
/// # Errors
///
/// Returns a refusal naming what is wrong with it, and the failure to read or seal it otherwise.
pub fn readmit(store: &kr_ipc::install::Store, manifest: &ReleaseManifest) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = store.release_directory(&manifest.release);
    let written = read_tree(&directory)?;
    check_files(manifest, &written)?;
    seal(&directory, manifest)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
        .and_then(|()| std::fs::File::open(store.versions()).and_then(|opened| opened.sync_all()))
        .map_err(|error| sealing(&directory, &error))
}

/// Takes the length and digest of every file under `tree`, refusing anything but files and
/// directories and any name that is not text.
fn read_tree(tree: &Path) -> Result<Written> {
    let unreadable = |error: &std::io::Error| {
        CliError::Other(shown!(
            "the release at {} could not be read: {}",
            Shown::root(tree),
            Shown::io(error)
        ))
    };
    let mut written = Written::new();
    let mut pending: Vec<(PathBuf, Vec<String>)> = vec![(tree.to_path_buf(), Vec::new())];
    while let Some((directory, relative)) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(|error| unreadable(&error))? {
            let entry = entry.map_err(|error| unreadable(&error))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| refused_tree(tree, "holds a name that is not text"))?;
            let kind = entry.file_type().map_err(|error| unreadable(&error))?;
            let mut path = relative.clone();
            path.push(name);
            if kind.is_dir() {
                pending.push((entry.path(), path));
            } else if kind.is_file() {
                let mut opened =
                    std::fs::File::open(entry.path()).map_err(|error| unreadable(&error))?;
                let summary = digest(&mut opened).map_err(|error| unreadable(&error))?;
                written.insert(path.join("/"), summary);
            } else {
                return Err(refused_tree(
                    tree,
                    "holds something that is neither a file nor a directory, such as a link",
                ));
            }
        }
    }
    Ok(written)
}

/// The length and digest of what `source` reads.
fn digest(source: &mut impl std::io::Read) -> std::io::Result<(u64, Digest256)> {
    let mut hasher = sha2::Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 256 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((length, Digest256::from_bytes(digest)))
}

fn sealing(path: &Path, error: &std::io::Error) -> CliError {
    CliError::Other(shown!(
        "the staged release could not be made read-only at {}: {}",
        Shown::root(path),
        Shown::io(error)
    ))
}

fn refused_archive(archive: &Path, reason: &'static str) -> CliError {
    CliError::Other(shown!(
        "the archive {} is not a release this host installs: it {}",
        Shown::root(archive),
        reason
    ))
}

fn refused_tree(tree: &Path, reason: &'static str) -> CliError {
    CliError::Other(shown!(
        "the release at {} is not one this host installs: it {}",
        Shown::root(tree),
        reason
    ))
}

fn write_failure(path: &Path, error: &std::io::Error) -> CliError {
    CliError::Other(shown!(
        "the release could not be staged at {}: {}",
        Shown::root(path),
        Shown::io(error)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path inside one top directory is split into it and the parts below; anything that could
    /// leave it, or is not text, is not.
    #[test]
    fn an_archive_entry_stays_inside_its_top_directory() {
        assert_eq!(
            split_entry(Path::new("kalareach/bin/kr")),
            Some((
                "kalareach".to_owned(),
                vec!["bin".to_owned(), "kr".to_owned()]
            ))
        );
        assert_eq!(
            split_entry(Path::new("./kalareach/bin")),
            Some(("kalareach".to_owned(), vec!["bin".to_owned()]))
        );
        for refused in [
            "/kalareach/bin/kr",
            "kalareach/../escape",
            "../escape",
            "",
            ".",
        ] {
            assert_eq!(split_entry(Path::new(refused)), None, "{refused}");
        }
    }

    /// This build names a target a release can be built for.
    #[test]
    fn this_build_names_a_release_target() {
        assert_ne!(this_target(), "unsupported");
    }
}
