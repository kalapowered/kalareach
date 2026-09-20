//! The environment's private staging area.
//!
//! One directory per environment, under the environment's state directory, with a random name.
//! Inside it, three areas that never mix:
//!
//! ```text
//! <state>/environments/<prefix>/transfers/
//!   transfers.sqlite
//!   <32 random hexadecimal characters>/
//!     incomplete/   uploads that are still receiving chunks
//!     complete/     verified, published attachments
//!     snapshots/    immutable download snapshots
//! ```
//!
//! Incomplete files live apart from completed ones, which is what section 14 paragraph 2 asks for:
//! nothing can read a partially written payload as though it were an attachment, because a
//! published handle names a file in a different directory.
//!
//! The area is 0700 on Unix. On Windows it is created with a protected access-control list holding
//! one entry for the object's owner and one inherit-only entry that becomes an owner entry on
//! everything created beneath it, so inheritance from the profile above cannot widen it.
//!
//! Creating it that way is half the rule. The other half is that the rules are checked on the
//! handle every time the area is opened, on both platforms: the owner and the mode on Unix, the
//! owner and every entry of the list on Windows. A directory that already existed with wider
//! access is refused rather than adopted, because nothing says this host is the one that created
//! it.
//!
//! The random name is not a secret and nothing depends on it staying unknown. It is there so two
//! installations, or an installation and a restored backup, never collide on a payload name, and
//! so a path guessed from a transfer identifier alone names nothing.

use std::path::Path;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::{EnvironmentId, TransferId};

use crate::authority::{AuthorisedDirectory, Privacy, RelativeName};
use crate::error::{Result, TransferError};

/// The directory, under the environment's state directory, that the transfer service owns.
pub const TRANSFERS_DIRECTORY: &str = "transfers";

/// The transfer store's filename inside that directory.
pub const STORE_FILE_NAME: &str = "transfers.sqlite";

/// Where uploads receive their chunks.
pub const INCOMPLETE_DIRECTORY: &str = "incomplete";

/// Where verified attachments are published.
pub const COMPLETE_DIRECTORY: &str = "complete";

/// Where download snapshots are staged.
pub const SNAPSHOTS_DIRECTORY: &str = "snapshots";

/// The extensions a staged payload may carry.
///
/// An allowlist rather than a denylist, because the question is not "which extensions can Windows
/// execute" (a list nobody can close) but "which extensions does an agent need". Section 14 permits
/// a *validated* extension to be retained for an agent that requires one, and these are the media,
/// document and text types an attachment is. Anything else keeps the bare identifier, which
/// executes nothing on any platform.
const PERMITTED_EXTENSIONS: &[&str] = &[
    // The four formats the preview decoder reads, plus the other image types an agent may accept.
    "png", "jpg", "jpeg", "webp", "gif", "bmp", "tif", "tiff", "heic", "heif", "avif", "svg", "ico",
    // Documents.
    "pdf", "txt", "md", "markdown", "rtf", "csv", "tsv", "json", "jsonl", "yaml", "yml", "toml",
    "xml", "html", "htm", "log", "diff", "patch", "ics", "vcf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "odt", "ods", "odp", "epub", "tex", "bib", // Audio and video.
    "mp3", "m4a", "aac", "wav", "flac", "ogg", "opus", "mp4", "m4v", "mov", "webm", "mkv", "avi",
    // Archives and the plain binary case.
    "zip", "gz", "bz2", "xz", "zst", "tar", "7z", "bin", "dat",
];

/// Longest extension a staged payload keeps.
const MAX_EXTENSION_LEN: usize = 16;

/// The three areas one environment stages transfers in.
#[derive(Debug)]
pub struct StagingArea {
    environment_id: EnvironmentId,
    identity: crate::authority::ObjectIdentity,
    incomplete: AuthorisedDirectory,
    complete: AuthorisedDirectory,
    snapshots: AuthorisedDirectory,
}

impl StagingArea {
    /// Returns the directory the transfer service owns inside an environment's state directory.
    #[must_use]
    pub fn root_of(paths: &EnvironmentPaths) -> std::path::PathBuf {
        paths.state_dir().join(TRANSFERS_DIRECTORY)
    }

    /// Returns the transfer store's path inside that directory.
    #[must_use]
    pub fn store_path(paths: &EnvironmentPaths) -> std::path::PathBuf {
        Self::root_of(paths).join(STORE_FILE_NAME)
    }

    /// Creates the transfer service's own directory, owner-only, and returns an authority for it.
    ///
    /// The store lives here and the private staging directory is created beneath it.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StagingUnavailable`] when the directory cannot be created, or
    /// exists with the wrong owner or wider permissions.
    pub fn prepare_root(paths: &EnvironmentPaths) -> Result<AuthorisedDirectory> {
        let root = Self::root_of(paths);
        kr_ipc::paths::create_private_tree(paths.state_root(), &root)
            .map_err(TransferError::staging)?;
        let root = AuthorisedDirectory::open_root(paths.environment_id(), &root)
            .map_err(TransferError::from)?;
        // The tree above this directory belongs to the installation rather than to this service,
        // so it is checked rather than created here: an owner other than this user, or access for
        // an account that does not already hold the machine, is a refusal.
        root.check_privacy(Privacy::OwnerOnly)
            .map_err(TransferError::from)?;
        Ok(root)
    }

    /// Returns a random staging-directory name.
    ///
    /// Thirty-two hexadecimal characters from the operating system's generator. It is a name, not
    /// a credential: the directory's permissions are what restrict it.
    #[must_use]
    pub fn random_name() -> String {
        let bytes = kr_ipc::new_uuid();
        let mut name = String::with_capacity(32);
        for byte in bytes.as_bytes() {
            name.push_str(&format!("{byte:02x}"));
        }
        name
    }

    /// Opens the three areas beneath a staging directory, creating whatever is missing.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::StagingUnavailable`] when a directory cannot be created or opened.
    pub fn open(root: &AuthorisedDirectory, staging_name: &str) -> Result<Self> {
        let name = RelativeName::parse(staging_name).map_err(|escape| {
            TransferError::staging(format!(
                "{staging_name} is not a staging directory: {escape}"
            ))
        })?;
        let staging = create_private_staging_directory(root, &name)?;
        Ok(Self {
            environment_id: root.environment_id(),
            identity: staging.identity(),
            incomplete: subdirectory(&staging, INCOMPLETE_DIRECTORY)?,
            complete: subdirectory(&staging, COMPLETE_DIRECTORY)?,
            snapshots: subdirectory(&staging, SNAPSHOTS_DIRECTORY)?,
        })
    }

    /// Returns the environment this area belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the identity of the staging directory the three areas live in.
    #[must_use]
    pub const fn identity(&self) -> crate::authority::ObjectIdentity {
        self.identity
    }

    /// Checks that this area is the one whose identity was recorded earlier.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Escape`] when the identities differ.
    pub fn check_identity(&self, expected: crate::authority::ObjectIdentity) -> Result<()> {
        if expected == self.identity {
            Ok(())
        } else {
            Err(TransferError::from(
                crate::authority::Escape::IdentityChanged {
                    detail: format!(
                        "this environment's staging directory was recorded as {expected} and now                          names {}",
                        self.identity
                    ),
                },
            ))
        }
    }

    /// Returns the area uploads receive chunks into.
    #[must_use]
    pub const fn incomplete(&self) -> &AuthorisedDirectory {
        &self.incomplete
    }

    /// Returns the area verified attachments are published into.
    #[must_use]
    pub const fn complete(&self) -> &AuthorisedDirectory {
        &self.complete
    }

    /// Returns the area download snapshots are staged into.
    #[must_use]
    pub const fn snapshots(&self) -> &AuthorisedDirectory {
        &self.snapshots
    }
}

fn subdirectory(staging: &AuthorisedDirectory, name: &str) -> Result<AuthorisedDirectory> {
    let name = RelativeName::parse(name).map_err(TransferError::from)?;
    staging
        .create_subdirectory(&name)
        .map_err(TransferError::from)
}

/// Creates the private staging directory itself, and checks what it carries.
///
/// A directory that already exists is the ordinary case on every start after the first, and it is
/// also the case this cannot take on trust: nothing says this host created it. So the rules are
/// checked on the handle that was just opened, every time, rather than assumed from the create.
fn create_private_staging_directory(
    root: &AuthorisedDirectory,
    name: &RelativeName,
) -> Result<AuthorisedDirectory> {
    let staging = build_private_staging_directory(root, name)?;
    staging
        .check_privacy(Privacy::Boundary)
        .map_err(TransferError::from)?;
    Ok(staging)
}

/// On Unix the ordinary owner-only create does everything: 0700 on the directory and 0600 on every
/// payload beneath it.
#[cfg(not(windows))]
fn build_private_staging_directory(
    root: &AuthorisedDirectory,
    name: &RelativeName,
) -> Result<AuthorisedDirectory> {
    root.create_subdirectory(name).map_err(TransferError::from)
}

/// On Windows the directory carries an explicit protected access-control list.
#[cfg(windows)]
fn build_private_staging_directory(
    root: &AuthorisedDirectory,
    name: &RelativeName,
) -> Result<AuthorisedDirectory> {
    // The list is applied at creation, by absolute path, because that is the one call Windows
    // offers for it. It happens once, at startup, inside the environment's own state directory;
    // every access after it is relative to the handle this returns. The directory is made the way
    // every other private directory of this host is, so one rule decides what the list says.
    let path = root.host_path(name);
    kr_ipc::paths::create_private_directory(&path)?;
    root.subdirectory(name).map_err(TransferError::from)
}

/// The name a transfer's payload is stored under.
///
/// Derived entirely from the transfer identifier. The original filename contributes at most a
/// validated extension: separators, traversal segments, reserved device names and everything else
/// a client might send never reach the storage path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageName {
    stem: String,
    extension: Option<String>,
}

impl StorageName {
    /// Derives the storage name of one transfer.
    #[must_use]
    pub fn derive(transfer_id: TransferId, original_file_name: &str) -> Self {
        let mut stem = String::with_capacity(32);
        for byte in transfer_id.get().as_bytes() {
            stem.push_str(&format!("{byte:02x}"));
        }
        Self {
            stem,
            extension: validated_extension(original_file_name),
        }
    }

    /// Returns the name a payload receives while it is still incomplete.
    ///
    /// The suffix is what makes an unfinished payload unmistakable even if the two areas were ever
    /// looked at together. The areas are separate directories regardless.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidArgument`] when the derived name is not a valid relative
    /// name, which a transfer identifier cannot cause.
    pub fn incomplete(&self) -> Result<RelativeName> {
        RelativeName::parse(&format!("{}.part", self.stem)).map_err(TransferError::from)
    }

    /// Returns the name a payload is published under.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::InvalidArgument`] when the derived name is not a valid relative
    /// name.
    pub fn published(&self) -> Result<RelativeName> {
        let name = match &self.extension {
            Some(extension) => format!("{}.{extension}", self.stem),
            None => self.stem.clone(),
        };
        RelativeName::parse(&name).map_err(TransferError::from)
    }

    /// Returns the extension that was kept, if any.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        self.extension.as_deref()
    }

    /// Returns the transfer a storage name belongs to, or `None` when the name is not one.
    ///
    /// Every payload name in the three staging areas is thirty-two hexadecimal characters plus an
    /// optional suffix, so a reconciliation pass can ask the journal about a name it found rather
    /// than guessing whether it is one of this service's.
    #[must_use]
    pub fn transfer_of(name: &str) -> Option<TransferId> {
        let stem = name.split('.').next().unwrap_or(name);
        if stem.len() != 32 || !stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (slot, pair) in bytes.iter_mut().zip(stem.as_bytes().chunks(2)) {
            let text = std::str::from_utf8(pair).ok()?;
            *slot = u8::from_str_radix(text, 16).ok()?;
        }
        Some(TransferId::new(kr_protocol::scalars::Uuid::from_bytes(
            bytes,
        )))
    }
}

/// Returns the extension a storage name may keep, or `None`.
///
/// An agent that needs a file to look like a PNG gets a `.png`. Everything else about the client's
/// name is discarded.
fn validated_extension(original_file_name: &str) -> Option<String> {
    // The basename is taken under both separators, because the name arrived from somewhere this
    // host does not choose and either one may be in it.
    let basename = original_file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(original_file_name);
    let (stem, extension) = basename.rsplit_once('.')?;
    if stem.is_empty() {
        // A dotfile has no extension; `.gitignore` is a name, not a suffix.
        return None;
    }
    if extension.is_empty() || extension.len() > MAX_EXTENSION_LEN {
        return None;
    }
    if !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let lowered = extension.to_ascii_lowercase();
    if !PERMITTED_EXTENSIONS.contains(&lowered.as_str()) {
        return None;
    }
    Some(lowered)
}

/// Returns true when a path lies inside a repository working tree.
///
/// Section 14 keeps uploads outside repositories. The check is the honest one a host can make from
/// a path alone: a `.git` entry at the path or above it. It is a guard against an accidental
/// destination, not a security boundary, and the staging area is outside every repository by
/// construction because it lives in the environment's state directory.
#[must_use]
pub fn inside_repository(path: &Path) -> bool {
    let mut current = Some(path);
    while let Some(directory) = current {
        if directory.join(".git").symlink_metadata().is_ok() {
            return true;
        }
        current = directory.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn transfer() -> TransferId {
        TransferId::new(Uuid::from_bytes([
            0x0a, 0x1b, 0x2c, 0x3d, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ]))
    }

    #[test]
    fn a_storage_name_comes_from_the_transfer_not_the_client() {
        let name = StorageName::derive(transfer(), "../../etc/passwd");
        assert_eq!(
            name.published().expect("a valid name").as_str(),
            "0a1b2c3d0405060708090a0b0c0d0e0f"
        );
        assert_eq!(
            name.incomplete().expect("a valid name").as_str(),
            "0a1b2c3d0405060708090a0b0c0d0e0f.part"
        );
    }

    #[test]
    fn a_validated_extension_is_kept_and_nothing_else_is() {
        assert_eq!(validated_extension("photo.PNG").as_deref(), Some("png"));
        assert_eq!(validated_extension("report.tar.gz").as_deref(), Some("gz"));
        // An allowlist, so anything not named keeps the bare identifier.
        assert_eq!(validated_extension("payload.ws"), None);
        assert_eq!(validated_extension("payload.wsc"), None);
        assert_eq!(validated_extension("payload.appref"), None);
        assert_eq!(validated_extension("payload.qqq"), None);
        assert_eq!(
            validated_extension("C:\\Users\\me\\photo.jpeg").as_deref(),
            Some("jpeg")
        );
        assert_eq!(validated_extension("no-extension"), None);
        assert_eq!(validated_extension(".gitignore"), None);
        assert_eq!(validated_extension("trailing."), None);
        assert_eq!(validated_extension("odd.p n g"), None);
        assert_eq!(validated_extension("long.aaaaaaaaaaaaaaaaa"), None);
        assert_eq!(validated_extension("payload.exe"), None);
        assert_eq!(validated_extension("payload.Ps1"), None);
        assert_eq!(validated_extension("payload.bat"), None);
        assert_eq!(validated_extension("payload.lnk"), None);
        assert_eq!(validated_extension("escape.png/../sh"), None);
    }

    #[test]
    fn a_traversal_extension_never_reaches_the_name() {
        let name = StorageName::derive(transfer(), "photo.png/../../evil");
        assert_eq!(name.extension(), None);
        let published = name.published().expect("a valid name");
        assert!(!published.as_str().contains('/'));
        assert!(!published.as_str().contains(".."));
    }

    #[test]
    fn a_device_name_never_reaches_the_storage_path() {
        for original in ["NUL", "nul.png", "con", "aux.txt", "COM1"] {
            let name = StorageName::derive(transfer(), original);
            let published = name.published().expect("a valid name");
            assert!(
                published.as_str().starts_with("0a1b2c3d"),
                "{original} produced {published}"
            );
        }
    }

    #[test]
    fn a_random_staging_name_is_thirty_two_hexadecimal_characters() {
        let first = StagingArea::random_name();
        let second = StagingArea::random_name();
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
        RelativeName::parse(&first).expect("a valid relative name");
    }

    #[test]
    fn the_three_areas_are_separate_directories() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority = AuthorisedDirectory::open_root(
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            root.path(),
        )
        .expect("opens the root");
        let staging_name = StagingArea::random_name();
        let area = StagingArea::open(&authority, &staging_name).expect("opens the areas");
        assert_ne!(area.incomplete().identity(), area.complete().identity());
        assert_ne!(area.complete().identity(), area.snapshots().identity());
        assert!(
            area.incomplete()
                .display_path()
                .ends_with(format!("{staging_name}/{INCOMPLETE_DIRECTORY}"))
        );
        // Opening the same area again finds the same directories rather than making new ones.
        let again = StagingArea::open(&authority, &staging_name).expect("opens the areas");
        assert_eq!(again.incomplete().identity(), area.incomplete().identity());
    }

    #[test]
    fn a_staging_area_refuses_a_name_that_is_not_a_single_component() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let authority = AuthorisedDirectory::open_root(
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            root.path(),
        )
        .expect("opens the root");
        assert!(StagingArea::open(&authority, "../elsewhere").is_err());
        assert!(StagingArea::open(&authority, "").is_err());
    }

    #[test]
    fn a_repository_is_recognised_from_a_path_and_the_staging_area_is_not_one() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let repository = root.path().join("project");
        std::fs::create_dir_all(repository.join(".git")).expect("creates");
        std::fs::create_dir_all(repository.join("src")).expect("creates");
        assert!(inside_repository(&repository));
        assert!(inside_repository(&repository.join("src")));
        let staging = root.path().join("state").join(TRANSFERS_DIRECTORY);
        std::fs::create_dir_all(&staging).expect("creates");
        assert!(!inside_repository(&staging));
    }
}
