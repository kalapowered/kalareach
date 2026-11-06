//! The libraries a macOS program loads that the system does not supply itself.
//!
//! The system's own libraries are built into a shared cache that the loader maps without opening
//! the files they would be in, so a program that loads only those needs no read rule for them, and
//! a profile that grants none still starts it. What a profile has to name is every other library:
//! one that a packaging of Git brings with it, such as the gettext and PCRE libraries Homebrew's
//! Git links.
//!
//! They are found the way the loader finds them, by reading each program's load commands and not
//! by running anything: the libraries a program names, the `@rpath` entries it carries, and the
//! same of each library found, until nothing new is named. A library is granted by the directory
//! it is in once every link in its name is resolved, because a profile judges the path a file has,
//! not the one it was opened by, and because Git and the libraries it loads open further modules
//! from the same directory while they run.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use object::macho;
use object::read::macho::{FatArch as _, LoadCommandVariant, MachHeader as _};
use object::{Architecture, Endianness, FileKind};

use crate::error::{ProjectError, Result};

/// The paths the system supplies its libraries from. A library named under one of them is in the
/// shared cache, and needs no rule.
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
    /// The `@rpath` entries of the images that loaded this one, each already expanded.
    inherited: Vec<PathBuf>,
}

/// What one image names.
struct Named {
    /// Each library it loads, and whether the loader may go on without it.
    libraries: Vec<(PathBuf, bool)>,
    /// Its own `@rpath` entries, as written.
    rpaths: Vec<PathBuf>,
}

/// Names the directories of the libraries the programs given, and every program in Git's helper
/// directory, load and the system does not supply, each resolved to the directory it is.
///
/// A file that is not a program, such as a script, names nothing and is passed over. One object
/// reached by several names is read once.
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
    let mut seen = HashSet::new();
    let mut loaded = HashSet::new();
    let mut directories = BTreeSet::new();
    for (candidate, required) in &candidates {
        let metadata = match std::fs::metadata(candidate) {
            Ok(metadata) => metadata,
            // A name in the helper directory that leads nowhere is nothing Git can start.
            Err(_) if !required => continue,
            Err(error) => return Err(unnamed(candidate, &error)),
        };
        if !metadata.is_file() || !seen.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        let file = std::fs::canonicalize(candidate).map_err(|error| unnamed(candidate, &error))?;
        let executable_directory = file.parent().unwrap_or(&file).to_owned();
        let mut pending = vec![Image {
            file,
            executable_directory,
            inherited: Vec::new(),
        }];
        while let Some(image) = pending.pop() {
            let Some(named) = read(&image.file)? else {
                continue;
            };
            let own: Vec<PathBuf> = named
                .rpaths
                .iter()
                .filter_map(|rpath| expand(rpath, &image))
                .collect();
            let search: Vec<PathBuf> = own.iter().chain(image.inherited.iter()).cloned().collect();
            for (name, weak) in &named.libraries {
                let Some(found) = find(name, &image, &search) else {
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
                directories.insert(library_directory(&library, name)?);
                if loaded.insert(library.clone()) {
                    pending.push(Image {
                        file: library,
                        executable_directory: image.executable_directory.clone(),
                        inherited: search.clone(),
                    });
                }
            }
        }
    }
    Ok(directories.into_iter().collect())
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
    for candidate in candidates {
        if supplied_by_the_system(&candidate) {
            return Some(Found::System);
        }
        if let Ok(resolved) = std::fs::canonicalize(&candidate)
            && resolved.is_file()
        {
            return Some(Found::File(resolved));
        }
    }
    None
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
/// A universal file is read at the slice for the machine this host runs on.
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
                .find(|arch| arch.architecture() == this_machine())
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
                .find(|arch| arch.architecture() == this_machine())
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
                named.libraries.push((
                    PathBuf::from(OsStr::from_bytes(name)),
                    command.cmd() == macho::LC_LOAD_WEAK_DYLIB,
                ));
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

/// Returns the architecture of the machine this host runs on.
fn this_machine() -> Architecture {
    if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else {
        Architecture::X86_64
    }
}

/// Returns the directory one library is in, and refuses a directory that is not one to grant as a
/// support directory.
fn library_directory(library: &Path, named: &Path) -> Result<PathBuf> {
    let directory = library.parent().unwrap_or(library).to_owned();
    if broad(&directory) {
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

/// Returns whether a support object lies in, or holds, a tree no support object may, or holds a
/// tree a support directory may only lie in.
fn broad(object: &Path) -> bool {
    NEVER_SUPPORT
        .iter()
        .map(Path::new)
        .any(|tree| object.starts_with(tree) || tree.starts_with(object))
        || NEVER_OVER
            .iter()
            .map(Path::new)
            .any(|tree| tree.starts_with(object))
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
        ] {
            assert!(broad(Path::new(broad_path)), "{broad_path} is broad");
        }
        for fine in [
            "/opt/homebrew/Cellar/gettext/1.0/lib",
            "/usr/local/Cellar/pcre2/10.4/lib",
            "/Users/someone/.local/git/lib",
            "/Library/Developer/CommandLineTools/usr/lib",
            "/Volumes/Tools/git/lib",
        ] {
            assert!(
                !broad(Path::new(fine)),
                "{fine} is a directory of libraries"
            );
        }
    }
}
