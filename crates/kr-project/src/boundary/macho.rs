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
//! not start inside the profile, or it refuses the set; both fail closed. The differences that
//! grant more are a name under a system path, which `find` explains; a library that two images
//! reach through different search paths, which is followed through the first image the walk goes
//! into it from, as the loader does, while the other image's name for it may lead to another file
//! that is granted too; and the first slice of a universal file that is this machine's kind of
//! program, whatever its subtype. A library is granted by the
//! directory it is in once every link in its name is resolved, because a profile judges the path a
//! file has, not the one it was opened by, and because Git and the libraries it loads open further
//! modules from the same directory while they run.

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
    let roots = Roots::account();
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
}

impl Walk<'_> {
    /// Goes into one image as the loader does: it finds everything the image names, and only then
    /// goes into each of those in the order they are named, so a library that two images name is
    /// gone into from the earlier of them, and what it names through `@rpath` is found through
    /// the search path of that image and of the ones above it.
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
            let Some(found) = find(name, image, &search) else {
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
fn find(name: &Path, image: &Image, search: &[PathBuf]) -> Option<Found> {
    let text = name.as_os_str().as_bytes();
    let candidates: Vec<PathBuf> = if let Some(rest) = text.strip_prefix(b"@rpath/") {
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

/// The home directory of the account this host runs as and its `Library`, which keep the
/// keychains, the applications' data and the credentials of a person, and so are no support
/// directory and are held by no support directory.
///
/// Each is kept by every name it can be compared by: the one it was given by, and the one it has
/// once every link in it is resolved. A library's directory is resolved before it is compared, so
/// a home reached through a link, a home that is not under `/Users` and a `Library` that was
/// moved elsewhere are each compared by the name the library's directory would have in them.
#[derive(Debug, Default)]
struct Roots {
    homes: Vec<PathBuf>,
    libraries: Vec<PathBuf>,
}

impl Roots {
    /// Returns the roots of the account this process runs as: the home its environment names and
    /// the one the system's account database gives.
    fn account() -> Self {
        Self::resolving(&account_homes())
    }

    /// Returns the roots of these homes, each by its own name and by its resolved one, and of the
    /// `Library` in each, by the same two.
    fn resolving(homes: &[PathBuf]) -> Self {
        let mut roots = Self::default();
        for home in homes.iter().filter(|home| home.is_absolute()) {
            let mut names = vec![home.clone()];
            names.extend(std::fs::canonicalize(home).ok());
            for name in names {
                let library = name.join("Library");
                let mut libraries = vec![library.clone()];
                libraries.extend(std::fs::canonicalize(&library).ok());
                push_new(&mut roots.homes, name);
                for root in libraries {
                    push_new(&mut roots.libraries, root);
                }
            }
        }
        roots
    }

    /// Returns whether an object is one of these roots, holds one, or is directly in one.
    fn hold(&self, object: &Path) -> bool {
        self.homes
            .iter()
            .chain(&self.libraries)
            .any(|root| root.starts_with(object) || object.parent() == Some(root))
    }
}

/// Adds a path to a list that does not hold it yet.
fn push_new(list: &mut Vec<PathBuf>, path: PathBuf) {
    if !list.contains(&path) {
        list.push(path);
    }
}

/// Returns the homes of the account this process runs as, by the two sources there are for them:
/// the `HOME` of its environment, and the home the system's account database gives its user, which
/// the environment cannot change.
fn account_homes() -> Vec<PathBuf> {
    homes_from(
        std::env::var_os("HOME").map(PathBuf::from),
        super::macos::passwd_home(),
    )
}

/// Returns the absolute ones of these two homes, once each.
fn homes_from(environment: Option<PathBuf>, database: Option<PathBuf>) -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = environment.into_iter().chain(database).collect();
    homes.retain(|home| home.is_absolute());
    homes.dedup();
    homes
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

    #[test]
    fn a_directory_that_holds_more_than_libraries_is_broad() {
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
            "/Volumes/Tools",
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
            "/Volumes/Tools/git/lib",
        ] {
            assert!(
                !broad(Path::new(fine), &Roots::default()),
                "{fine} is a directory of libraries"
            );
        }
    }

    /// A directory to build a home in, next to the test program, which no rule about the system's
    /// own trees refuses, and its own name with every link in it resolved.
    fn scratch() -> (tempfile::TempDir, PathBuf) {
        let program = std::env::current_exe().expect("the test program's own path");
        let directory = tempfile::Builder::new()
            .prefix("kr-macho-")
            .tempdir_in(program.parent().expect("the program is in a directory"))
            .expect("a directory to build in");
        let root = std::fs::canonicalize(directory.path()).expect("the directory's own name");
        (directory, root)
    }

    /// Makes these directories.
    fn make(paths: &[PathBuf]) {
        for path in paths {
            std::fs::create_dir_all(path).expect("a directory");
        }
    }

    #[test]
    fn a_home_reached_through_a_link_is_held_by_the_name_a_library_has() {
        let (_directory, root) = scratch();
        let home = root.join("real").join("alice");
        make(&[
            home.join(".ssh"),
            home.join("Library").join("Keychains"),
            home.join("tools").join("lib"),
            root.join("real").join("bob").join("lib"),
        ]);
        std::os::unix::fs::symlink("real/alice", root.join("via")).expect("a link to the home");
        // The account is told its home by the link, and a library is found by the home itself.
        let roots = Roots::resolving(&[root.join("via")]);
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
    fn a_library_directory_moved_elsewhere_is_held_where_it_now_is() {
        let (_directory, root) = scratch();
        let home = root.join("alice");
        let moved = root.join("elsewhere").join("Library");
        make(&[
            home.clone(),
            moved.join("Keychains"),
            moved.join("Application Support").join("tool").join("lib"),
            root.join("other").join("lib"),
        ]);
        std::os::unix::fs::symlink(&moved, home.join("Library")).expect("a link to the Library");
        let roots = Roots::resolving(std::slice::from_ref(&home));
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
        let (_directory, root) = scratch();
        let home = root.join("real").join("alice");
        make(&[home.join("Library"), home.join("tools").join("lib")]);
        std::os::unix::fs::symlink("real/alice", root.join("via")).expect("a link to the home");
        let roots = Roots::resolving(&[root.join("via")]);
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
        let home = |path: &str| Some(PathBuf::from(path));
        assert_eq!(
            homes_from(home("/Volumes/One/me"), home("/Users/me")),
            [PathBuf::from("/Volumes/One/me"), PathBuf::from("/Users/me")],
            "both are kept when they differ"
        );
        assert_eq!(
            homes_from(None, home("/Users/me")),
            [PathBuf::from("/Users/me")]
        );
        assert_eq!(
            homes_from(home("/Users/me"), home("/Users/me")),
            [PathBuf::from("/Users/me")],
            "and once when they do not"
        );
        assert!(
            homes_from(home("relative/me"), None).is_empty(),
            "a home that is not absolute names nothing"
        );

        let passwd = super::super::macos::passwd_home().expect("the system names a home");
        assert!(
            passwd.is_absolute() && passwd.is_dir(),
            "{}",
            passwd.display()
        );
        assert!(
            account_homes().contains(&passwd),
            "the account's homes hold it"
        );
        assert!(Roots::account().hold(&passwd), "and so do its roots");
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

        let found = find(name, &image, &[missing.clone(), own.clone()]);
        assert!(
            matches!(&found, Some(Found::File(file)) if *file == own.join("libkr.dylib")),
            "the library after the system path is found"
        );
        // The controls: with no other candidate the system supplies the name, and with none at
        // all it is not found.
        assert!(matches!(
            find(name, &image, std::slice::from_ref(&missing)),
            Some(Found::System)
        ));
        assert!(find(name, &image, &[]).is_none());
    }
}
