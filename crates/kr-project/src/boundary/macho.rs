//! The libraries a macOS program loads that the system does not supply itself.
//!
//! The system's own libraries are built into a shared cache that the loader maps without opening
//! the files they would be in, so a program that loads only those needs no read rule for them, and
//! a profile that grants none still starts it. What a profile has to name is every other library:
//! one that a packaging of Git brings with it, such as the gettext and PCRE libraries Homebrew's
//! Git links.
//!
//! They are found the way the loader finds them, so far as the load commands show it, by reading
//! each program's load commands and not by running anything: the libraries a program names, the
//! `@rpath` entries it carries, and the same of each library found, until nothing new is named.
//! Where this host differs from the loader it leaves a library ungranted, so that the program does
//! not start inside the profile, or it refuses the set; both fail closed. The walk goes into the
//! libraries in the order the loader does, gives each the search path of the image it is gone into
//! from, and, for an `@rpath` name, uses a library already found whose install name is that name
//! before it searches, as the loader reuses an image it has loaded. The differences that remain
//! grant more: a name under a system path, which `find` explains, and the first slice of a
//! universal file that is this machine's kind of program, whatever its subtype. A library is
//! granted by the directory it is in once every link in its name is resolved, because a profile
//! judges the path a file has, not the one it was opened by, and because Git and the libraries it
//! loads open further modules from the same directory while they run.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use object::macho;
use object::read::macho::{FatArch as _, LoadCommandVariant, MachHeader as _};
use object::{Endianness, FileKind};

use crate::error::{ProjectError, Result};

/// The paths the system supplies its libraries from. A library named under one of them is in the
/// shared cache, and needs no rule. A file there that the cache does not hold is not granted
/// either, and the program that loads it does not start inside the profile.
const SYSTEM: &[&str] = &["/usr/lib/", "/System/Library/"];

/// The trees a support object may neither lie in nor hold: the devices, the system's
/// configuration, and the machine's shared temporary and state directories, where any program of
/// the account can put something.
const NEVER_SUPPORT: &[&str] = &[
    "/dev",
    "/etc",
    "/tmp",
    "/var",
    "/private/etc",
    "/private/tmp",
    "/private/var",
];

/// The trees a support directory may lie in but not be or hold: each holds a great deal besides
/// libraries. A Git installed in one of them has its libraries in a directory of its own there,
/// and granting that directory grants nothing else in the tree.
const NEVER_OVER: &[&str] = &[
    "/usr",
    "/opt",
    "/Users",
    "/Library",
    "/Applications",
    "/System",
    "/Volumes",
    "/Network",
    "/private",
    "/home",
    "/cores",
];

/// One program or library whose dependencies are still to be read.
struct Image {
    /// The file, with every link in its name resolved.
    file: PathBuf,
    /// The directory of the program the loader started, which `@executable_path` names.
    executable_directory: PathBuf,
    /// The `@rpath` entries of the images the walk went through to reach this one, nearest first,
    /// each already expanded.
    inherited: Vec<PathBuf>,
}

/// What one image names.
#[derive(Clone)]
struct Named {
    /// Each library it loads, and whether the loader may go on without it.
    libraries: Vec<(PathBuf, bool)>,
    /// Its own `@rpath` entries, as written.
    rpaths: Vec<PathBuf>,
    /// The name a library gives itself, which a name that asks for it can be the same text as.
    install_name: Option<PathBuf>,
}

/// Names the directories of the libraries the programs given, and every program in Git's helper
/// directory, load and the system does not supply, each resolved to the directory it is.
///
/// Each program is followed on its own, from where the loader would start it: what `@rpath`
/// entries and `@executable_path` mean to a library depends on the program that loaded it, so two
/// programs that load one library each get the dependencies that library has for them. A file that
/// is not a program, such as a script, names nothing and is passed over. A program reached through
/// links is the file they lead to, which is what the loader names it by; one reached by another
/// name that is not a link is a program of its own, and each file is read once however often it
/// is reached.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] naming the object that could not be named: a file that
/// could not be read or is a program of a kind this host does not read, a library the loader would
/// not find, and a library in a directory that is not one to grant.
pub fn support_set(programs: &[&Path], helper_directory: &Path) -> Result<Vec<PathBuf>> {
    let mut candidates: Vec<(PathBuf, bool)> = programs
        .iter()
        .map(|program| ((*program).to_owned(), true))
        .collect();
    let entries =
        std::fs::read_dir(helper_directory).map_err(|error| unnamed(helper_directory, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| unnamed(helper_directory, &error))?;
        candidates.push((entry.path(), false));
    }
    let mut reader = Reader::default();
    let roots = Roots::account()?;
    let mut seen = HashSet::new();
    let mut directories = BTreeSet::new();
    for (candidate, required) in &candidates {
        let metadata = match std::fs::metadata(candidate) {
            Ok(metadata) => metadata,
            // A name in the helper directory that leads nowhere is nothing Git can start.
            Err(_) if !required => continue,
            Err(error) => return Err(unnamed(candidate, &error)),
        };
        if !metadata.is_file() {
            continue;
        }
        let file = std::fs::canonicalize(candidate).map_err(|error| unnamed(candidate, &error))?;
        if !seen.insert(file.clone()) {
            continue;
        }
        let executable_directory = file.parent().unwrap_or(&file).to_owned();
        let mut walk = Walk {
            reader: &mut reader,
            roots: &roots,
            directories: &mut directories,
            entered: HashSet::from([file.clone()]),
            loaded: HashMap::new(),
        };
        walk.go_into(&Image {
            file,
            executable_directory,
            inherited: Vec::new(),
        })?;
    }
    Ok(directories.into_iter().collect())
}

/// One program's walk through the libraries it loads.
struct Walk<'a> {
    reader: &'a mut Reader,
    roots: &'a Roots,
    directories: &'a mut BTreeSet<PathBuf>,
    /// The files the walk has gone into. A library is gone into once for a program, from the
    /// first image the walk goes into it from.
    entered: HashSet<PathBuf>,
    /// The libraries the walk has found, by the install name each gives itself: the first one
    /// found under a name is the one the loader reuses for that name.
    loaded: HashMap<PathBuf, PathBuf>,
}

impl Walk<'_> {
    /// Goes into one image as the loader does: it finds everything the image names, and only then
    /// goes into each of those in the order they are named, so a library that two images name is
    /// gone into from the earlier of them, and what it names through `@rpath` is found through
    /// the search path of that image and of the ones above it. An `@rpath` name that a library
    /// found earlier gives as its own install name is that library, with no search.
    fn go_into(&mut self, image: &Image) -> Result<()> {
        let Some(named) = self.reader.named(&image.file)? else {
            return Ok(());
        };
        let own: Vec<PathBuf> = named
            .rpaths
            .iter()
            .filter_map(|rpath| expand(rpath, image))
            .collect();
        let search: Vec<PathBuf> = own.iter().chain(image.inherited.iter()).cloned().collect();
        let mut found_here = Vec::new();
        for (name, weak) in &named.libraries {
            let Some(found) = find(name, image, &search, &self.loaded) else {
                if *weak {
                    continue;
                }
                return Err(ProjectError::GitFailed {
                    detail: format!(
                        "{} loads {}, which this host does not find, so the support set of an \
                         invocation for a caller bounded by a grant cannot be named",
                        crate::git::redact(&image.file.display().to_string()),
                        crate::git::redact(&shown(name))
                    )
                    .into(),
                });
            };
            let Found::File(library) = found else {
                continue;
            };
            self.directories
                .insert(library_directory(&library, name, self.roots)?);
            if let Some(installed) = self.reader.named(&library)?.and_then(|n| n.install_name) {
                self.loaded
                    .entry(installed)
                    .or_insert_with(|| library.clone());
            }
            found_here.push(library);
        }
        for library in found_here {
            if self.entered.insert(library.clone()) {
                self.go_into(&Image {
                    file: library,
                    executable_directory: image.executable_directory.clone(),
                    inherited: search.clone(),
                })?;
            }
        }
        Ok(())
    }
}

/// What each object names, read once however many programs load it: the libraries and `@rpath`
/// entries of a file are the file's own, and only what they lead to depends on who loads it.
#[derive(Default)]
struct Reader(HashMap<(u64, u64), Option<Named>>);

impl Reader {
    /// Returns what the file names, or nothing for a file that is not a program or a library.
    fn named(&mut self, file: &Path) -> Result<Option<Named>> {
        let metadata = std::fs::metadata(file).map_err(|error| unnamed(file, &error))?;
        let key = (metadata.dev(), metadata.ino());
        if let Some(named) = self.0.get(&key) {
            return Ok(named.clone());
        }
        let named = read(file)?;
        self.0.insert(key, named.clone());
        Ok(named)
    }
}

/// What the loader finds for one name.
enum Found {
    /// The system supplies it from its shared cache.
    System,
    /// A file, with every link in its name resolved.
    File(PathBuf),
}

/// Finds the library a name leads to, the way the loader looks for it.
///
/// `loaded` holds the libraries found so far by their install names.
fn find(
    name: &Path,
    image: &Image,
    search: &[PathBuf],
    loaded: &HashMap<PathBuf, PathBuf>,
) -> Option<Found> {
    let text = name.as_os_str().as_bytes();
    let candidates: Vec<PathBuf> = if let Some(rest) = text.strip_prefix(b"@rpath/") {
        // The loader looks for an image it has loaded whose install name is this name before it
        // searches, and uses it when it has one.
        if let Some(file) = loaded.get(name) {
            return Some(Found::File(file.clone()));
        }
        search
            .iter()
            .map(|rpath| rpath.join(OsStr::from_bytes(rest)))
            .collect()
    } else if let Some(rest) = text.strip_prefix(b"@loader_path/") {
        let directory = image.file.parent()?;
        vec![directory.join(OsStr::from_bytes(rest))]
    } else if let Some(rest) = text.strip_prefix(b"@executable_path/") {
        vec![image.executable_directory.join(OsStr::from_bytes(rest))]
    } else if name.is_absolute() {
        vec![name.to_owned()]
    } else {
        Vec::new()
    };
    // A name under a system path is in the shared cache unless the cache does not hold it, and
    // what the cache holds is not known here. So the search goes on past such a candidate: a later
    // candidate that is a file is granted, and the system supplies the name only when no later one
    // is. Where the cache did hold the name, the loader takes that, and this grants one more
    // directory, one the program's own search path names, and reads that library's names too,
    // which can refuse the set for a name the loader would never have looked for.
    let mut system = false;
    for candidate in candidates {
        if supplied_by_the_system(&candidate) {
            system = true;
            continue;
        }
        if let Ok(resolved) = std::fs::canonicalize(&candidate)
            && resolved.is_file()
        {
            return Some(Found::File(resolved));
        }
    }
    system.then_some(Found::System)
}

/// Returns whether a path is one the system supplies its libraries from.
fn supplied_by_the_system(path: &Path) -> bool {
    SYSTEM
        .iter()
        .any(|prefix| path.as_os_str().as_bytes().starts_with(prefix.as_bytes()))
}

/// Expands one `@rpath` entry of an image into the directory it names, or nothing for an entry
/// the loader would not take.
fn expand(rpath: &Path, image: &Image) -> Option<PathBuf> {
    let text = rpath.as_os_str().as_bytes();
    if text == b"@loader_path" {
        image.file.parent().map(Path::to_owned)
    } else if let Some(rest) = text.strip_prefix(b"@loader_path/") {
        Some(image.file.parent()?.join(OsStr::from_bytes(rest)))
    } else if text == b"@executable_path" {
        Some(image.executable_directory.clone())
    } else if let Some(rest) = text.strip_prefix(b"@executable_path/") {
        Some(image.executable_directory.join(OsStr::from_bytes(rest)))
    } else if rpath.is_absolute() {
        Some(rpath.to_owned())
    } else {
        None
    }
}

/// Reads the load commands of one file, or nothing for a file that is not a program or a library.
///
/// A universal file is read at the slice for the machine this host runs on, and a file of one
/// architecture is read only when it is that one: a program of another, which the system could run
/// under translation, loads the libraries of its own architecture, and this host reads no others.
fn read(file: &Path) -> Result<Option<Named>> {
    let data = std::fs::read(file).map_err(|error| unnamed(file, &error))?;
    let unread = |why: &str| ProjectError::GitFailed {
        detail: format!(
            "{} is {why}, so the support set of an invocation for a caller bounded by a grant \
             cannot be named",
            crate::git::redact(&file.display().to_string())
        )
        .into(),
    };
    let slice: &[u8] = match FileKind::parse(data.as_slice()) {
        Ok(FileKind::MachO64) => &data,
        Ok(FileKind::MachOFat32) => {
            let fat = object::read::macho::MachOFatFile32::parse(data.as_slice())
                .map_err(|_| unread("a universal file whose headers this host cannot read"))?;
            let arch = fat
                .arches()
                .iter()
                .find(|arch| arch.cputype() == this_machine())
                .ok_or_else(|| unread("a universal file with nothing for this machine"))?;
            arch.data(data.as_slice())
                .map_err(|_| unread("a universal file whose slice this host cannot read"))?
        }
        Ok(FileKind::MachOFat64) => {
            let fat = object::read::macho::MachOFatFile64::parse(data.as_slice())
                .map_err(|_| unread("a universal file whose headers this host cannot read"))?;
            let arch = fat
                .arches()
                .iter()
                .find(|arch| arch.cputype() == this_machine())
                .ok_or_else(|| unread("a universal file with nothing for this machine"))?;
            arch.data(data.as_slice())
                .map_err(|_| unread("a universal file whose slice this host cannot read"))?
        }
        Ok(FileKind::MachO32) => return Err(unread("a program of a kind this host does not read")),
        // A script, or any other file that is not a program: it names no library.
        _ => return Ok(None),
    };
    let header = macho::MachHeader64::<Endianness>::parse(slice, 0)
        .map_err(|_| unread("a program whose headers this host cannot read"))?;
    let endian = header
        .endian()
        .map_err(|_| unread("a program whose headers this host cannot read"))?;
    if header.cputype(endian) != this_machine() {
        return Err(unread(
            "a program built for another kind of machine than this one",
        ));
    }
    let mut commands = header
        .load_commands(endian, slice, 0)
        .map_err(|_| unread("a program whose load commands this host cannot read"))?;
    let mut named = Named {
        libraries: Vec::new(),
        rpaths: Vec::new(),
        install_name: None,
    };
    while let Some(command) = commands
        .next()
        .map_err(|_| unread("a program whose load commands this host cannot read"))?
    {
        match command
            .variant()
            .map_err(|_| unread("a program whose load commands this host cannot read"))?
        {
            LoadCommandVariant::Dylib(dylib) => {
                let name = command
                    .string(endian, dylib.dylib.name)
                    .map_err(|_| unread("a program that names a library this host cannot read"))?;
                // Linked weakly either by the command that says so or by the flag the newer
                // encoding of a load command carries.
                let flags = command
                    .dylib_use_flags(endian, dylib)
                    .map_err(|_| unread("a program that names a library this host cannot read"))?;
                let weak = command.cmd() == macho::LC_LOAD_WEAK_DYLIB
                    || flags.is_some_and(|flags| flags & macho::DYLIB_USE_WEAK_LINK != 0);
                named
                    .libraries
                    .push((PathBuf::from(OsStr::from_bytes(name)), weak));
            }
            LoadCommandVariant::IdDylib(dylib) => {
                let name = command
                    .string(endian, dylib.dylib.name)
                    .map_err(|_| unread("a library whose own name this host cannot read"))?;
                named.install_name = Some(PathBuf::from(OsStr::from_bytes(name)));
            }
            LoadCommandVariant::Rpath(rpath) => {
                let path = command
                    .string(endian, rpath.path)
                    .map_err(|_| unread("a program that names a path this host cannot read"))?;
                named.rpaths.push(PathBuf::from(OsStr::from_bytes(path)));
            }
            _ => {}
        }
    }
    Ok(Some(named))
}

/// Returns the processor type of the machine this host runs on, as a file names it.
fn this_machine() -> u32 {
    if cfg!(target_arch = "aarch64") {
        macho::CPU_TYPE_ARM64
    } else {
        macho::CPU_TYPE_X86_64
    }
}

/// Returns the directory one library is in, and refuses a directory that is not one to grant as a
/// support directory.
fn library_directory(library: &Path, named: &Path, roots: &Roots) -> Result<PathBuf> {
    let directory = library.parent().unwrap_or(library).to_owned();
    if broad(&directory, roots) {
        return Err(ProjectError::GitFailed {
            detail: format!(
                "{} is in {}, which is not a directory this host grants as a support directory, so \
                 the support set of an invocation for a caller bounded by a grant cannot be named",
                crate::git::redact(&shown(named)),
                crate::git::redact(&directory.display().to_string())
            )
            .into(),
        });
    }
    Ok(directory)
}

/// What a directory is, whatever it is called: the device it is on and its number there, which
/// every name of the directory shares, the data volume's spelling of a path as much as the plain
/// one.
type Identity = (u64, u64);

/// Returns the identity of the directory a name leads to, nothing for a name that is not there,
/// and the error for any other failure.
fn identity_of(path: &Path) -> std::io::Result<Option<Identity>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// One protected directory: who it is, and who it and everything above it is.
#[derive(Debug)]
struct Root {
    identity: Identity,
    /// The identities of the directory itself and of every directory above it, by the names it
    /// was given and found under.
    above: Vec<Identity>,
}

/// The home directory of the account this host runs as and its `Library`, which keep the
/// keychains, the applications' data and the credentials of a person, and so are no support
/// directory and are held by no support directory.
///
/// A directory is compared by what it is and not by what it is called, with the directories above
/// it: a home reached through a link, a home that is not under `/Users`, a `Library` that was
/// moved elsewhere and either of them under the data volume's spelling of its path are each the
/// directory a library's directory would be compared with. The names that lead to them are
/// followed to where they end, because what is above a home is where the home is.
#[derive(Debug, Default)]
struct Roots {
    roots: Vec<Root>,
}

impl Roots {
    /// Returns the roots of the account this process runs as: the home its environment names and
    /// the one the system's account database gives.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the account database gives no home or a home or
    /// a `Library` cannot be examined, since a protection that is partly missing is not one.
    fn account() -> Result<Self> {
        let homes = homes_from(
            std::env::var_os("HOME").map(PathBuf::from),
            super::macos::passwd_home(),
        )?;
        Self::resolving(&homes)
    }

    /// Returns the roots of these homes and of the `Library` in each, a name that is not there
    /// holding nothing.
    fn resolving(homes: &[PathBuf]) -> Result<Self> {
        let mut roots = Self::default();
        for home in homes.iter().filter(|home| home.is_absolute()) {
            let mut names = vec![home.clone()];
            names.extend(resolved(home)?);
            for name in names {
                roots.add(&name)?;
                if let Some(moved) = resolved(&name.join("Library"))? {
                    roots.add(&moved)?;
                }
            }
        }
        Ok(roots)
    }

    /// Adds the directory a name leads to, with every directory above the name.
    fn add(&mut self, name: &Path) -> Result<()> {
        let Some(identity) = identity_of(name).map_err(|error| unexamined(name, &error))? else {
            return Ok(());
        };
        let mut above = Vec::new();
        for ancestor in name.ancestors() {
            if let Some(found) =
                identity_of(ancestor).map_err(|error| unexamined(ancestor, &error))?
                && !above.contains(&found)
            {
                above.push(found);
            }
        }
        // The same directory under another name is above other directories, so the two are one
        // root holding what is above either.
        match self.roots.iter_mut().find(|root| root.identity == identity) {
            Some(root) => {
                for found in above {
                    if !root.above.contains(&found) {
                        root.above.push(found);
                    }
                }
            }
            None => self.roots.push(Root { identity, above }),
        }
        Ok(())
    }

    /// Returns whether a directory is one of these roots, holds one, or is directly in one. A
    /// name that is not there is none of them, and a directory that cannot be examined is held
    /// back.
    fn hold(&self, object: &Path) -> bool {
        let Ok(here) = identity_of(object) else {
            return true;
        };
        let parent = match object.parent().map(identity_of) {
            None => None,
            Some(Ok(parent)) => parent,
            Some(Err(_)) => return true,
        };
        self.roots.iter().any(|root| {
            here.is_some_and(|here| root.above.contains(&here))
                || parent.is_some_and(|parent| parent == root.identity)
        })
    }
}

/// Returns the name a path has once every link in it is resolved, nothing for a path that is not
/// there, and the refusal for any other failure.
fn resolved(path: &Path) -> Result<Option<PathBuf>> {
    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(Some(resolved)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(unexamined(path, &error)),
    }
}

/// Returns the refusal for a protected directory that could not be examined.
fn unexamined(path: &Path, error: &std::io::Error) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!(
            "{} could not be examined to find the directories this host's account keeps its own \
             in, so the support set of an invocation for a caller bounded by a grant cannot be \
             named: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    }
}

/// Returns the homes of the account this process runs as, by the two sources there are for them:
/// the `HOME` of its environment, and the home the system's account database gives its user, which
/// the environment cannot change. The database must answer.
fn homes_from(
    environment: Option<PathBuf>,
    database: std::io::Result<PathBuf>,
) -> Result<Vec<PathBuf>> {
    let database = database.map_err(|error| ProjectError::GitFailed {
        detail: format!(
            "the system's account database gives no home for the account this host runs as, so \
             the support set of an invocation for a caller bounded by a grant cannot be named: \
             {error}"
        )
        .into(),
    })?;
    let mut homes: Vec<PathBuf> = environment.into_iter().chain([database]).collect();
    homes.retain(|home| home.is_absolute());
    homes.dedup();
    Ok(homes)
}

/// Returns whether a support object lies in, or holds, a tree no support object may, or holds a
/// tree a support directory may only lie in, or is the top of one: a directory directly in such a
/// tree is a volume, a package prefix or a bundle, and holds a great deal besides libraries. So is
/// a person's home, the directories directly in it and those directly in its `Library`, where the
/// keychains and the applications' data are kept: the homes under `/Users` by their names, and the
/// account's own by the names `Roots` keeps, with whatever holds them.
fn broad(object: &Path, roots: &Roots) -> bool {
    let directly_in = |trees: &[&str]| {
        object
            .parent()
            .is_some_and(|parent| trees.iter().any(|tree| parent == Path::new(tree)))
    };
    NEVER_SUPPORT
        .iter()
        .map(Path::new)
        .any(|tree| object.starts_with(tree) || tree.starts_with(object))
        || NEVER_OVER
            .iter()
            .map(Path::new)
            .any(|tree| tree.starts_with(object))
        || directly_in(NEVER_OVER)
        || object
            .strip_prefix("/Users")
            .ok()
            .and_then(|rest| rest.components().next())
            .is_some_and(|name| near_a_home(object, &Path::new("/Users").join(name)))
        || roots.hold(object)
}

/// Returns whether an object is a home directory, directly in it, or directly in its `Library`.
fn near_a_home(object: &Path, home: &Path) -> bool {
    let Ok(rest) = object.strip_prefix(home) else {
        return false;
    };
    let mut parts = rest.components();
    match (parts.next(), parts.next(), parts.next()) {
        (None, ..) | (Some(_), None, _) => true,
        (Some(first), Some(_), None) => first.as_os_str() == "Library",
        _ => false,
    }
}

/// Returns the name a library is loaded by, as a message repeats it.
///
/// The `@` that starts `@rpath` and its siblings is one this host does not repeat from text it did
/// not write, and a message holding one is replaced whole, so the name is shown without it.
fn shown(name: &Path) -> String {
    name.display().to_string().replacen('@', "", 1)
}

/// Returns a refusal naming the object that could not be named for a support set.
fn unnamed(path: &Path, error: &std::io::Error) -> ProjectError {
    ProjectError::GitFailed {
        detail: format!(
            "{} could not be read to name the support set of an invocation for a caller bounded by \
             a grant: {error}",
            crate::git::redact(&path.display().to_string())
        )
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The root of the volumes is spelled in two parts so the repository's record check does not
    // read a test path as a volume of the machine the work was done on.
    const VOLUMES: &str = concat!("/Volume", "s");

    #[test]
    fn a_directory_that_holds_more_than_libraries_is_broad() {
        let volume = format!("{VOLUMES}/Tools");
        let volume_library = format!("{VOLUMES}/Tools/git/lib");
        for broad_path in [
            "/",
            "/usr",
            "/opt",
            "/Users",
            "/Library",
            "/private/var/folders/ab/cd/T/kr-1",
            "/private/tmp/kr-1",
            "/private/etc",
            "/dev",
            // A person's home, what is kept at the top of it, the shared directory and the top of
            // a volume or of a package prefix hold more than a library.
            "/Users/someone",
            "/Users/someone/Library",
            "/Users/someone/Documents",
            "/Users/someone/Library/Keychains",
            "/Users/someone/Library/Application Support",
            "/Users/Shared",
            volume.as_str(),
            "/opt/homebrew",
            "/usr/local",
            "/Applications/Tool.app",
        ] {
            assert!(
                broad(Path::new(broad_path), &Roots::default()),
                "{broad_path} is broad"
            );
        }
        for fine in [
            "/opt/homebrew/Cellar/gettext/1.0/lib",
            "/opt/homebrew/lib",
            "/usr/local/Cellar/pcre2/10.4/lib",
            "/usr/local/lib",
            "/Users/someone/.local/git/lib",
            "/Users/someone/tools/lib",
            "/Users/someone/Library/Application Support/tool/lib",
            "/Library/Developer/CommandLineTools/usr/lib",
            "/Applications/Xcode.app/Contents/Developer/usr/lib",
            volume_library.as_str(),
        ] {
            assert!(
                !broad(Path::new(fine), &Roots::default()),
                "{fine} is a directory of libraries"
            );
        }
    }

    /// A directory to build a home in, next to the test program, and its own name with every link
    /// in it resolved; nothing, with a line saying so, where that place is one no support
    /// directory may be in, which would refuse the controls for another reason.
    fn scratch() -> Option<(tempfile::TempDir, PathBuf)> {
        let program = std::env::current_exe().expect("the test program's own path");
        let directory = tempfile::Builder::new()
            .prefix("kr-macho-")
            .tempdir_in(program.parent().expect("the program is in a directory"))
            .expect("a directory to build in");
        let root = std::fs::canonicalize(directory.path()).expect("the directory's own name");
        if broad(&root.join("lib"), &Roots::default()) {
            println!("not exercised: the test program is in a place no support directory may be");
            return None;
        }
        Some((directory, root))
    }

    /// Makes these directories.
    fn make(paths: &[PathBuf]) {
        for path in paths {
            std::fs::create_dir_all(path).expect("a directory");
        }
    }

    #[test]
    fn a_home_reached_through_a_link_is_held_by_the_name_a_library_has() {
        let Some((_directory, root)) = scratch() else {
            return;
        };
        let home = root.join("real").join("alice");
        make(&[
            home.join(".ssh"),
            home.join("Library").join("Keychains"),
            home.join("tools").join("lib"),
            root.join("real").join("bob").join("lib"),
        ]);
        std::os::unix::fs::symlink("real/alice", root.join("via")).expect("a link to the home");
        // The account is told its home by the link, and a library is found by the home itself.
        let roots = Roots::resolving(&[root.join("via")]).expect("the roots are found");
        for held in [
            home.clone(),
            home.join(".ssh"),
            home.join("Library"),
            home.join("Library").join("Keychains"),
            root.join("real"),
            root.clone(),
        ] {
            assert!(roots.hold(&held), "{} is held", held.display());
            assert!(
                broad(&held, &roots),
                "and is no support directory: {}",
                held.display()
            );
        }
        // The controls: what is in the home deeper than its top, and a neighbour.
        for free in [
            home.join("tools").join("lib"),
            root.join("real").join("bob").join("lib"),
        ] {
            assert!(!roots.hold(&free), "{} is not held", free.display());
            assert!(
                !broad(&free, &roots),
                "and is a directory of libraries: {}",
                free.display()
            );
        }
    }

    #[test]
    fn a_home_is_the_same_root_by_the_data_volumes_spelling_and_by_the_plain_one() {
        // A directory on the data volume, which the system presents under two names: its own and
        // the data volume's, `/System/Volumes/Data` followed by it.
        let directory = tempfile::TempDir::new().expect("a directory on the data volume");
        let plain = std::fs::canonicalize(directory.path()).expect("the directory's own name");
        let spelled = Path::new("/System/Volumes/Data").join(
            plain
                .strip_prefix("/")
                .expect("an absolute path has a root"),
        );
        if !spelled.is_dir() {
            println!("not exercised: this host presents no data volume under /System");
            return;
        }
        let home = plain.join("alice");
        let moved = plain.join("elsewhere").join("Library");
        make(&[
            home.join(".ssh"),
            home.join("tools").join("lib"),
            moved.join("Keychains"),
            moved.join("Application Support").join("tool").join("lib"),
        ]);
        std::os::unix::fs::symlink(
            spelled.join("elsewhere").join("Library"),
            home.join("Library"),
        )
        .expect("a link to the Library by the data volume's name");
        let by = |base: &Path, parts: &[&str]| parts.iter().fold(base.to_owned(), |p, x| p.join(x));

        // The account is told its home by the data volume's spelling, and a library is found by
        // the plain one, and the other way round.
        for (given, asked) in [(&spelled, &plain), (&plain, &spelled)] {
            let roots = Roots::resolving(&[given.join("alice")]).expect("the roots are found");
            for held in [
                by(asked, &["alice"]),
                by(asked, &["alice", ".ssh"]),
                by(asked, &["elsewhere", "Library"]),
                by(asked, &["elsewhere", "Library", "Keychains"]),
                asked.clone(),
            ] {
                assert!(
                    roots.hold(&held),
                    "{} is held, the home given as {}",
                    held.display(),
                    given.display()
                );
            }
            for free in [
                by(asked, &["alice", "tools", "lib"]),
                by(
                    asked,
                    &["elsewhere", "Library", "Application Support", "tool", "lib"],
                ),
            ] {
                assert!(
                    !roots.hold(&free),
                    "{} is not, the home given as {}",
                    free.display(),
                    given.display()
                );
            }
        }
    }

    #[test]
    fn a_home_with_no_library_reached_through_a_link_holds_what_is_above_where_it_is() {
        let Some((_directory, root)) = scratch() else {
            return;
        };
        let home = root.join("real").join("carol");
        make(&[home.join(".ssh"), home.join("tools").join("lib")]);
        std::os::unix::fs::symlink("real/carol", root.join("via")).expect("a link to the home");
        let roots = Roots::resolving(&[root.join("via")]).expect("the roots are found");
        for held in [
            home.clone(),
            home.join(".ssh"),
            root.join("real"),
            root.clone(),
        ] {
            assert!(roots.hold(&held), "{} is held", held.display());
        }
        assert!(
            !roots.hold(&home.join("tools").join("lib")),
            "the controls are not"
        );
    }

    #[test]
    fn a_library_directory_moved_elsewhere_is_held_where_it_now_is() {
        let Some((_directory, root)) = scratch() else {
            return;
        };
        let home = root.join("alice");
        let moved = root.join("elsewhere").join("Library");
        make(&[
            home.clone(),
            moved.join("Keychains"),
            moved.join("Application Support").join("tool").join("lib"),
            root.join("other").join("lib"),
        ]);
        std::os::unix::fs::symlink(&moved, home.join("Library")).expect("a link to the Library");
        let roots = Roots::resolving(std::slice::from_ref(&home)).expect("the roots are found");
        for held in [
            moved.clone(),
            moved.join("Keychains"),
            moved.join("Application Support"),
            root.join("elsewhere"),
        ] {
            assert!(
                broad(&held, &roots),
                "{} is held where the Library now is",
                held.display()
            );
        }
        for free in [
            moved.join("Application Support").join("tool").join("lib"),
            root.join("other").join("lib"),
        ] {
            assert!(
                !broad(&free, &roots),
                "{} is a directory of libraries",
                free.display()
            );
        }
    }

    #[test]
    fn a_library_in_a_home_is_refused_by_the_name_it_has_through_a_link() {
        let Some((_directory, root)) = scratch() else {
            return;
        };
        let home = root.join("real").join("alice");
        make(&[home.join("Library"), home.join("tools").join("lib")]);
        std::os::unix::fs::symlink("real/alice", root.join("via")).expect("a link to the home");
        let roots = Roots::resolving(&[root.join("via")]).expect("the roots are found");
        let refusal = library_directory(
            &home.join("Library").join("libkr.dylib"),
            Path::new("@rpath/libkr.dylib"),
            &roots,
        )
        .expect_err("a library at the top of a Library is no support object");
        assert!(
            refusal
                .to_string()
                .contains("not a directory this host grants"),
            "and the refusal says why: {refusal}"
        );
        assert_eq!(
            library_directory(
                &home.join("tools").join("lib").join("libkr.dylib"),
                Path::new("@rpath/libkr.dylib"),
                &roots
            )
            .expect("a library deeper in the home is a support object"),
            home.join("tools").join("lib")
        );
    }

    #[test]
    fn the_homes_of_the_account_are_named_by_its_environment_and_by_the_system() {
        let given = |path: &str| Some(PathBuf::from(path));
        let database = |path: &str| Ok(PathBuf::from(path));
        let other_volume = format!("{VOLUMES}/One/me");
        assert_eq!(
            homes_from(given(&other_volume), database("/Users/me")).expect("both are found"),
            [PathBuf::from(&other_volume), PathBuf::from("/Users/me")],
            "both are kept when they differ"
        );
        assert_eq!(
            homes_from(None, database("/Users/me")).expect("the database answers"),
            [PathBuf::from("/Users/me")],
            "the database alone is enough"
        );
        assert_eq!(
            homes_from(given("/Users/me"), database("/Users/me")).expect("both are found"),
            [PathBuf::from("/Users/me")],
            "and once when they do not differ"
        );
        assert_eq!(
            homes_from(given("relative/me"), database("/Users/me")).expect("the database answers"),
            [PathBuf::from("/Users/me")],
            "a home that is not absolute names nothing"
        );
        let failure = std::io::Error::other("the database did not answer");
        let refusal = homes_from(given("/Users/me"), Err(failure))
            .expect_err("the set is refused when the database gives no home");
        assert!(
            refusal.to_string().contains("account database"),
            "and says why: {refusal}"
        );
    }

    /// Runs the test program again with the environment of the account taken away, to show that
    /// the roots do not depend on it: the home the account database gives is held whatever
    /// `HOME` says, or whether it says anything.
    #[test]
    fn the_roots_hold_the_home_the_account_database_gives_whatever_the_environment_says() {
        if std::env::var_os("KR_MACHO_CHILD").is_some() {
            let passwd = super::super::macos::passwd_home().expect("the system names a home");
            let roots = Roots::account().expect("the roots of the account are found");
            assert!(roots.hold(&passwd), "the home the database gives is held");
            println!("KR_MACHO_CHILD checked {}", passwd.display());
            return;
        }
        let program = std::env::current_exe().expect("the test program's own path");
        let output = std::process::Command::new(program)
            .args([
                "--exact",
                "boundary::macho::tests::the_roots_hold_the_home_the_account_database_gives_whatever_the_environment_says",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KR_MACHO_CHILD", "1")
            .env_remove("HOME")
            .output()
            .expect("the test program starts again");
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && said.contains("KR_MACHO_CHILD checked"),
            "the roots hold it with no HOME: {said} {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_home_or_a_library_that_cannot_be_examined_refuses_the_roots() {
        let Some((_directory, root)) = scratch() else {
            return;
        };
        // A link that leads to itself cannot be resolved, which is not the same as a name that is
        // not there.
        std::os::unix::fs::symlink("loop", root.join("loop")).expect("a link that leads to itself");
        let refusal = Roots::resolving(&[root.join("loop")])
            .expect_err("a home that cannot be resolved refuses the roots");
        assert!(
            refusal.to_string().contains("could not be examined"),
            "and says so: {refusal}"
        );

        let home = root.join("alice");
        make(std::slice::from_ref(&home));
        std::os::unix::fs::symlink("Library", home.join("Library"))
            .expect("a Library that leads to itself");
        Roots::resolving(&[home]).expect_err("a Library that cannot be resolved refuses the roots");

        // The controls: a name that is not there holds nothing and refuses nothing.
        let roots = Roots::resolving(&[root.join("nobody")]).expect("a home that is not there");
        assert!(roots.roots.is_empty());
        let home = root.join("bob");
        make(std::slice::from_ref(&home));
        let roots = Roots::resolving(&[home]).expect("a home with no Library");
        assert!(!roots.roots.is_empty());
    }

    #[test]
    fn an_install_name_a_library_already_found_gives_is_used_before_a_search() {
        let Some((_directory, root)) = scratch() else {
            return;
        };
        make(&[root.join("found"), root.join("searched")]);
        std::fs::write(root.join("searched").join("libkr.dylib"), "").expect("a library");
        std::fs::write(root.join("found").join("libkr.dylib"), "").expect("a library");
        let image = Image {
            file: root.join("program"),
            executable_directory: root.clone(),
            inherited: Vec::new(),
        };
        let name = Path::new("@rpath/libkr.dylib");
        let search = [root.join("searched")];
        let loaded = HashMap::from([(name.to_owned(), root.join("found").join("libkr.dylib"))]);
        assert!(
            matches!(
                find(name, &image, &search, &loaded),
                Some(Found::File(file)) if file == root.join("found").join("libkr.dylib")
            ),
            "the library already found answers the name"
        );
        // The control: with none found, the search decides.
        assert!(
            matches!(
                find(name, &image, &search, &HashMap::new()),
                Some(Found::File(file)) if file == root.join("searched").join("libkr.dylib")
            ),
            "the search answers it otherwise"
        );
    }

    #[test]
    fn a_name_under_a_system_path_that_is_not_there_does_not_stop_the_search() {
        let root = tempfile::TempDir::new().expect("a directory");
        let own = std::fs::canonicalize(root.path()).expect("the directory's own name");
        std::fs::write(own.join("libkr.dylib"), "").expect("a library");
        let image = Image {
            file: own.join("program"),
            executable_directory: own.clone(),
            inherited: Vec::new(),
        };
        let name = Path::new("@rpath/libkr.dylib");
        let missing = PathBuf::from("/usr/lib/kr-no-such-directory");

        let found = find(
            name,
            &image,
            &[missing.clone(), own.clone()],
            &HashMap::new(),
        );
        assert!(
            matches!(&found, Some(Found::File(file)) if *file == own.join("libkr.dylib")),
            "the library after the system path is found"
        );
        // The controls: with no other candidate the system supplies the name, and with none at
        // all it is not found.
        assert!(matches!(
            find(
                name,
                &image,
                std::slice::from_ref(&missing),
                &HashMap::new()
            ),
            Some(Found::System)
        ));
        assert!(find(name, &image, &[], &HashMap::new()).is_none());
    }
}
