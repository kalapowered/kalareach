//! The folders of a case's project and the repository's files in them.

use std::fs;
use std::path::{Path, PathBuf};

use kr_boundary_windows::win::ffi::Sid;

use super::{Scratch, run};

/// The repository's configuration: what Git writes for a repository of its own, shortened.
pub const CONFIG: &str =
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n";

/// The folders of a case's project: `base\t\mid\parent\root`, with its `.git` inside the root.
pub struct Project {
    pub base: PathBuf,
    pub top: PathBuf,
    pub mid: PathBuf,
    pub parent: PathBuf,
    pub root: PathBuf,
    pub git: PathBuf,
}

/// Makes the repository's files in `root\.git`: the objects and refs folders, `config` and `HEAD`.
/// Returns the `.git` folder.
pub fn repository_at(root: &Path) -> PathBuf {
    let git = root.join(".git");
    fs::create_dir_all(git.join("objects")).unwrap();
    fs::create_dir_all(git.join("refs")).unwrap();
    fs::write(git.join("config"), CONFIG).unwrap();
    fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    git
}

impl Project {
    /// Makes the folders and the repository's files. Everyone has full control by inheritance, so
    /// that no refusal below comes from an access list.
    pub fn make(scratch: &Scratch, label: &str) -> Project {
        let base = scratch.path(label);
        fs::create_dir_all(&base).unwrap();
        run(
            "icacls",
            &[base.to_str().unwrap(), "/grant", "*S-1-1-0:(OI)(CI)F"],
        );
        Project::laid_out(base)
    }

    /// Makes the folders and the repository's files for a person alone: the lists give the person,
    /// the system and the administrators full control and nobody else anything, so that a refusal
    /// below comes from the list a case adds.
    pub fn make_private(scratch: &Scratch, label: &str, person: &Sid) -> Project {
        let base = scratch.path(label);
        fs::create_dir_all(&base).unwrap();
        run(
            "icacls",
            &[
                base.to_str().unwrap(),
                "/grant",
                &format!("*{}:(OI)(CI)F", person.to_text().unwrap()),
            ],
        );
        Project::laid_out(base)
    }

    fn laid_out(base: PathBuf) -> Project {
        let top = base.join("t");
        let mid = top.join("mid");
        let parent = mid.join("parent");
        let root = parent.join("root");
        let git = repository_at(&root);
        Project {
            base,
            top,
            mid,
            parent,
            root,
            git,
        }
    }
}
