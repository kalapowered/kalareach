//! What makes a release one this host installs, and putting one into the store.
//!
//! A release is taken in only whole and checked, in this order: its files are written where
//! nothing runs them, under the store's `staging/`, each read once and its digest taken as it is
//! written; its manifest is checked against the update channel's root, a threshold of the release
//! keys that root names having signed it; every file it lists is there with its length and digest,
//! and nothing it does not list is; it is for this system; it lists every program a host needs;
//! and only then is it made read-only, flushed, and renamed into `versions/` in one step. Nothing
//! a release carries is trusted before its manifest is, and nothing of it is used until it is all
//! there.
//!
//! An archive is refused at the first entry that could put something outside the release or be
//! something other than a file: a link, a device, a path that is absolute or climbs out of the
//! archive's one top directory. What the archive says about a file's mode or owner is not read:
//! a file is a program when the manifest says it is.

use std::collections::BTreeMap;
use std::io::Write as _;
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

    /// Takes a root the store kept, and checks it against itself as a release's is checked.
    ///
    /// # Errors
    ///
    /// Returns a refusal when it is not signed by its own root keys.
    pub fn kept(signed: tough::schema::Signed<tough::schema::Root>) -> Result<Self> {
        signed.signed.verify_role(&signed).map_err(|_| {
            CliError::Other(Shown::said(
                "the update channel's root this host kept is not signed by the root keys it names",
            ))
        })?;
        Ok(Self { signed })
    }

    /// The root as the store keeps it.
    #[must_use]
    pub fn to_kept(&self) -> tough::schema::Signed<tough::schema::Root> {
        self.signed.clone()
    }

    /// The root's version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.signed.signed.version.get()
    }

    /// Whether `other` is this very root.
    #[must_use]
    pub fn is(&self, other: &Self) -> bool {
        self.signed == other.signed
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
    /// its targets role signed the manifest, and the manifest lists files and stores a host can take.
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
                "the release's manifest is not one this build reads, or lists files or stores a \
                 host cannot take",
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
            "the release's manifest is not one this build reads, or lists files or stores a host \
             cannot take",
        ))
    })
}

/// Reads a file of a release whole, refusing one longer than `limit`, a link and a pipe: it is
/// never followed and never waited for.
fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    kr_ipc::install::read_regular_file(path, limit)
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

/// How long the system's own tool that says its version is given.
const TOOL_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How many bytes a tool may print: the tool that says a version prints a short line, and one that
/// prints more than this is given up on.
const TOOL_OUTPUT: usize = 4096;

/// Runs `program` and returns what it printed, or nothing when it does not end and say it within
/// `within`, prints more than [`TOOL_OUTPUT`], or leaves a pipe that cannot be read, in which case
/// it is ended. Its output is read
/// without blocking, in the loop that waits for it to end, so that a descendant that keeps the pipe
/// open after the tool has exited holds the run for the bound and no longer, and one that writes
/// without end is given up on at once. The pipe is closed with the run.
fn run_bounded(
    program: &str,
    arguments: &[&str],
    within: std::time::Duration,
) -> Option<std::process::Output> {
    use std::io::Read as _;

    let mut child = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let ended = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let Some(mut pipe) = child.stdout.take() else {
        ended(&mut child);
        return None;
    };
    if rustix::fs::fcntl_setfl(&pipe, rustix::fs::OFlags::NONBLOCK).is_err() {
        ended(&mut child);
        return None;
    }
    let deadline = std::time::Instant::now() + within;
    let mut printed = Vec::new();
    let mut status = None;
    let mut open = true;
    loop {
        while open {
            if std::time::Instant::now() >= deadline {
                ended(&mut child);
                return None;
            }
            let mut buffer = [0_u8; 512];
            match pipe.read(&mut buffer) {
                Ok(0) => open = false,
                Ok(read) => {
                    printed.extend_from_slice(&buffer[..read]);
                    if printed.len() > TOOL_OUTPUT {
                        ended(&mut child);
                        return None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                // A pipe that cannot be read says nothing of where the output ended.
                Err(_) => {
                    ended(&mut child);
                    return None;
                }
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(finished)) => status = Some(finished),
                Ok(None) => {}
                Err(_) => {
                    ended(&mut child);
                    return None;
                }
            }
        }
        if let Some(status) = status
            && !open
        {
            return Some(std::process::Output {
                status,
                stdout: printed,
                stderr: Vec::new(),
            });
        }
        if std::time::Instant::now() >= deadline {
            ended(&mut child);
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
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
    let output = run_bounded(program, arguments, TOOL_WAIT)?;
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

/// Opens an archive for reading without waiting for a writer: a pipe named as an archive would
/// otherwise hold the run for ever, under the update lock. A link is followed, since a person may
/// name an archive by one; what it leads to is checked to be a regular file.
fn open_archive(path: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(std::io::Error::from)
}

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
    let file = open_archive(archive).map_err(|error| unreadable(&error))?;
    if !file
        .metadata()
        .map_err(|error| unreadable(&error))?
        .is_file()
    {
        return Err(refused_archive(archive, "is not a regular file"));
    }
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
        // A sparse entry is a file written with its holes left out, which the tar crate's builder
        // does of a file that has some, on the systems that say so. It is refused, and said to
        // be, rather than read as the link or device it is not: a release archive has every file
        // whole.
        // The POSIX form of a sparse file is a regular entry that carries `GNU.sparse.*` extension
        // keys, which this reading does not expand either.
        let sparse_by_extension = match entry.pax_extensions() {
            Ok(Some(extensions)) => extensions
                .flatten()
                .any(|extension| extension.key_bytes().starts_with(b"GNU.sparse.")),
            Ok(None) => false,
            Err(error) => return Err(unreadable(&error)),
        };
        if kind.is_gnu_sparse() || sparse_by_extension {
            return Err(refused_archive(
                archive,
                "has a sparse entry, which a release's archive does not use: write every file \
                 whole",
            ));
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(refused_kind(archive, kind.as_byte()));
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

/// Checks that the release lists every program a host of its target needs, as programs: a release
/// without one is refused whole, whatever else it holds and whoever signed it.
///
/// What is listed here is the release's own account of itself, and [`check_files`] has already held
/// the files to it. This holds the account to what a host runs: the command line, its restoration
/// guard, the control daemon, the worker, the description process, the forwarder and the plugin
/// host, each a program of `bin/`.
///
/// # Errors
///
/// Returns a refusal naming each program the manifest does not list.
pub fn check_programs(manifest: &ReleaseManifest) -> Result<()> {
    let missing = manifest.missing_programs();
    if missing.is_empty() {
        return Ok(());
    }
    Err(CliError::Other(shown!(
        "the release does not list every program of bin/ that a host needs: it lacks {}",
        Shown::joined(missing.into_iter().map(|name| shown!("`{}`", name)), ", ")
    )))
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

/// The characters tar's entry kinds are written with, from `!` to `~`.
const GRAPHIC: &str = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// The refusal of an entry that is neither a file nor a directory, saying which kind it is by the
/// character tar gives it, with its usual name: `2` is a symbolic link, `1` a hard link.
fn refused_kind(archive: &Path, kind: u8) -> CliError {
    let said = |kind: Shown| {
        shown!(
            "the archive {} is not a release this host installs: it has an entry of type {} that \
             is neither a file nor a directory, such as a link or a device",
            Shown::root(archive),
            kind
        )
    };
    CliError::Other(match kind {
        b'1' => said(Shown::said("1, a hard link")),
        b'2' => said(Shown::said("2, a symbolic link")),
        b'3' => said(Shown::said("3, a character device")),
        b'4' => said(Shown::said("4, a block device")),
        b'6' => said(Shown::said("6, a pipe")),
        // A kind with no usual name is shown as tar writes it: by its character where it has one.
        other if other.is_ascii_graphic() => {
            let at = usize::from(other - b'!');
            said(Shown::said(&GRAPHIC[at..=at]))
        }
        other => said(shown!("{}", other)),
    })
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

    /// A tool that does not end is given a bound and ended, and one that ends is read.
    #[test]
    fn the_system_s_tool_is_given_a_bound_and_no_more() {
        let began = std::time::Instant::now();
        assert!(run_bounded("sleep", &["30"], std::time::Duration::from_millis(200)).is_none());
        assert!(
            began.elapsed() < std::time::Duration::from_secs(20),
            "the wait ended at its bound"
        );
        // A tool that ends while a descendant of it keeps its output open is not waited for past
        // the bound either: the pipe stays open until the descendant ends.
        let began = std::time::Instant::now();
        assert!(
            run_bounded(
                "sh",
                &["-c", "sleep 40 & echo hello"],
                std::time::Duration::from_millis(300)
            )
            .is_none()
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(30),
            "the wait ended at its bound, not when the descendant did"
        );
        // The control: a tool that ends is read.
        let output = run_bounded("echo", &["hello"], std::time::Duration::from_secs(20))
            .expect("echo ends and says something");
        assert_eq!(output.stdout, b"hello\n");
    }

    /// A tool that writes without end is given up on at once, not read for as long as it writes:
    /// with a bound far beyond the watchdog, only the limit on what it may print ends the run.
    #[test]
    fn a_tool_that_never_stops_writing_is_given_up_on() {
        // On a thread of its own, so that a run that reads for ever fails the test and does not
        // hang it.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let output = run_bounded("yes", &[], std::time::Duration::from_secs(600));
            let _ = sender.send(output.is_none());
        });
        let given_up = receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the run of a tool that writes for ever ended");
        assert!(given_up, "what it wrote is not returned");
    }

    /// When the bound of a tool that a descendant keeps the output of ends, this run's end of the
    /// pipe is closed: nothing of it stays open, on a thread or otherwise, until the descendant
    /// ends. The descendant says what it finds when it writes: the pipe closed, or, as the control,
    /// open while the run still reads it. It says so in a file, which is waited for, and writes
    /// ten seconds after a bound of one, so that only a stall of nine seconds could reorder them.
    #[test]
    fn a_tool_s_pipe_is_closed_when_its_bound_ends() {
        let directory = tempfile::tempdir().expect("a directory");
        // The descendant writes after `seconds` and records whether the write went through; SIGPIPE
        // is ignored, so a closed pipe is an error to it and not its end. The write is a program's
        // own, so that a shell's buffer does not carry what it could not write into the file.
        let script = |seconds: u32| {
            format!(
                "(trap '' PIPE; sleep {seconds}; if /bin/echo late; then echo open > \"$1\"; else echo \
                 closed > \"$1\"; fi) & echo hello"
            )
        };
        let told = |flag: &std::path::Path| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !flag.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // What the descendant wrote is complete once it ends in a newline.
            while std::time::Instant::now() < deadline {
                let text = std::fs::read_to_string(flag).unwrap_or_default();
                if text.ends_with('\n') {
                    return text;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            String::new()
        };
        // The bound ends while the descendant holds the pipe, and its write finds it closed.
        let closed = directory.path().join("closed");
        assert!(
            run_bounded(
                "sh",
                &["-c", &script(10), "sh", &closed.display().to_string()],
                std::time::Duration::from_secs(1)
            )
            .is_none(),
            "the descendant holds the pipe past the bound"
        );
        assert_eq!(
            told(&closed),
            "closed\n",
            "the pipe was closed at the bound"
        );
        // The control: where the run waits for the descendant, its write goes through and is read.
        let open = directory.path().join("open");
        let output = run_bounded(
            "sh",
            &["-c", &script(1), "sh", &open.display().to_string()],
            std::time::Duration::from_secs(120),
        )
        .expect("the run ends when the descendant does");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("late"),
            "the write of a descendant is read while the run waits"
        );
        assert_eq!(told(&open), "open\n");
    }

    /// A release's manifest that is a pipe is refused at once, and one that is a link is not
    /// followed, where the update reads it.
    #[test]
    fn a_manifest_that_is_a_pipe_or_a_link_is_refused_at_once() {
        let directory = tempfile::tempdir().expect("a directory");
        let release = directory.path().join("release");
        std::fs::create_dir(&release).expect("a release");
        let began = std::time::Instant::now();
        let made = std::process::Command::new("mkfifo")
            .arg(release.join(MANIFEST_FILE))
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe is made");
        assert!(manifest_document(&release).is_err());
        std::fs::remove_file(release.join(MANIFEST_FILE)).expect("the pipe goes");
        std::fs::write(directory.path().join("elsewhere.json"), b"{}").expect("a file elsewhere");
        std::os::unix::fs::symlink(
            directory.path().join("elsewhere.json"),
            release.join(MANIFEST_FILE),
        )
        .expect("a link");
        assert!(manifest_document(&release).is_err());
        assert!(
            began.elapsed() < std::time::Duration::from_secs(20),
            "neither was waited for"
        );
        // The control: a regular file is read.
        std::fs::remove_file(release.join(MANIFEST_FILE)).expect("the link goes");
        std::fs::write(release.join(MANIFEST_FILE), b"{}").expect("a manifest");
        assert_eq!(manifest_document(&release).expect("reads"), b"{}");
    }
}
