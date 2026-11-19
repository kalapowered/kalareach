//! Which package, if any, an agent word that the host does not compile in is declared by, and the
//! places a declaration may not name.

use std::path::{Component, Path, PathBuf};

use kr_plugin_sdk::skill_target::{COMPILED_WORDS, SkillTarget};

/// One admitted package's declaration, read from its verified connector table.
#[derive(Clone, Debug)]
pub(crate) struct Declaration {
    /// What it declares.
    pub(crate) target: SkillTarget,
}

/// What the declarations say of one word.
#[derive(Debug)]
pub(crate) enum Pick<'a> {
    /// One of the six compiled words: the compiled layout is used and no declaration is served.
    Compiled,
    /// Exactly one admitted package declares it.
    One(&'a Declaration),
    /// No admitted package declares it.
    Nobody,
    /// More than one admitted package declares it, so none is served.
    Taken,
}

/// Picks the declaration of `word` from the declarations of the admitted packages that hold the
/// capability. A declaration that names a compiled word is never served over the compiled layout.
pub(crate) fn pick<'a>(word: &str, declarations: &'a [Declaration]) -> Pick<'a> {
    if COMPILED_WORDS.contains(&word) {
        return Pick::Compiled;
    }
    let mut found = declarations
        .iter()
        .filter(|declaration| declaration.target.word == word);
    match (found.next(), found.next()) {
        (None, _) => Pick::Nobody,
        (Some(only), None) => Pick::One(only),
        (Some(_), Some(_)) => Pick::Taken,
    }
}

/// The refusal of a word that more than one admitted package declares.
const TAKEN: &str =
    "{word} is named by more than one package this host admits, so it installs for none of them";

/// The declaration that serves `word`: the one admitted package's, none for a word the host
/// compiles in or one nobody declares (the installer then refuses it by name), and the refusal
/// where more than one package declares it.
pub(crate) fn served(
    word: &str,
    declarations: &[Declaration],
) -> Result<Option<SkillTarget>, String> {
    match pick(word, declarations) {
        Pick::One(declaration) => Ok(Some(declaration.target.clone())),
        Pick::Compiled | Pick::Nobody => Ok(None),
        Pick::Taken => Err(TAKEN.replace("{word}", word)),
    }
}

/// The capability a package holds in its admission to declare an agent word.
const CAPABILITY: &str = "skill_target.install";

/// The directory and hash of each admitted package whose current grants hold the capability: the
/// only packages whose tables are read for a declared word. A package admitted without the
/// capability, or whose grant was taken back, is not read, whatever its table says.
pub(crate) fn holding_the_capability(
    packages: &[kr_protocol::admission::AdmittedPackage],
) -> Vec<(String, kr_protocol::scalars::Digest256)> {
    packages
        .iter()
        .filter(|package| package.grants.iter().any(|name| name == CAPABILITY))
        .map(|package| (package.package_dir.clone(), package.package_digest))
        .collect()
}

/// The refusal when the admissions changed while the packages were read.
const ADMISSIONS_MOVED: &str =
    "the packages this host admits changed while this request was read; ask again";

/// Whether the admissions are the ones the packages were read under: `now` is the revision read
/// again just before the registration of the action, none where it could not be read in time. A
/// request whose admissions moved is refused before the marker; what is left is the time between
/// this read and the registration.
pub(crate) fn admissions_held(read_at: u64, now: Option<u64>) -> Result<(), &'static str> {
    match now {
        Some(revision) if revision == read_at => Ok(()),
        _ => Err(ADMISSIONS_MOVED),
    }
}

/// The last check of a declared word's request, run after every check that reads the file system
/// and immediately before the action is registered: the revision the packages were read under,
/// `read_at`, against the revision `reread` reads now. A word the host compiles in was read under
/// none, so `reread` is not asked for it.
pub(crate) async fn admissions_held_until_registration(
    read_at: Option<u64>,
    reread: impl std::future::Future<Output = Option<u64>>,
) -> Result<(), &'static str> {
    match read_at {
        Some(read_at) => admissions_held(read_at, reread.await),
        None => Ok(()),
    }
}

/// The refusal of a declared word on a platform where the host does not walk the tree by handle.
#[must_use]
pub(crate) fn platform_refusal(on_windows: bool) -> Option<&'static str> {
    on_windows.then_some(
        "this host installs the contact skill for an agent that a package names on macOS and \
         Linux only; on Windows it installs it for codex, claude-code, opencode, gemini-cli, \
         kimi-code-cli and qoder-cli",
    )
}

/// The folders this host keeps for itself under the home folder when nothing moves them, and the
/// folder its records are in: the four defaults of its state, runtime, store and configuration.
#[must_use]
pub(crate) fn default_host_folders(home: &Path, records: &Path) -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = [
        ".local/state/kalareach",
        ".cache/kalareach/run",
        ".local/share/kalareach/host",
        ".config/kalareach",
    ]
    .iter()
    .map(|folder| home.join(folder))
    .collect();
    if let Some(state) = records.parent() {
        folders.push(state.to_path_buf());
    }
    folders
}

/// The folders this host keeps for its own files as it resolved them for this process, wherever
/// a variable put them: its state root, its runtime root, its store, and the folder of its
/// configuration where the platform keeps one apart from the state.
#[must_use]
pub(crate) fn resolved_host_folders(
    state_root: &Path,
    runtime_root: &Path,
    store: Option<PathBuf>,
    configuration: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut folders = vec![state_root.to_path_buf()];
    folders.push(runtime_root.to_path_buf());
    folders.extend(store);
    folders.extend(configuration);
    folders
}

/// `path` as the file system reaches it: the part of it that exists with every link resolved, and
/// the rest as written. A host folder that is not there yet, or a place that is not, still has the
/// location it will have.
#[must_use]
pub(crate) fn resolved(path: &Path) -> PathBuf {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        if let Ok(canonical) = std::fs::canonicalize(existing) {
            return missing
                .iter()
                .rev()
                .fold(canonical, |reached, name: &&std::ffi::OsStr| {
                    reached.join(name)
                });
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name);
                existing = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// True when `place` is inside one of `folders`, the folders this host keeps for its own files.
/// ASCII case is ignored, so a file system that does not tell `Kalareach` from `kalareach` is not a
/// way round.
#[must_use]
pub(crate) fn inside_host_folders(folders: &[PathBuf], place: &Path) -> bool {
    let components = |path: &Path| -> Vec<String> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
                _ => None,
            })
            .collect()
    };
    let place = components(place);
    folders
        .iter()
        .map(|folder| components(folder))
        .any(|folder| !folder.is_empty() && place.starts_with(&folder))
}
