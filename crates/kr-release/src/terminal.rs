//! The terminal a release was qualified against: its capability manifest and its terminfo database.
//!
//! A release carries `share/terminal-capabilities.json`, the manifest of the fixtures that fix what
//! the terminal does, and `share/terminfo/`, the compiled `xterm-256color` database the worker
//! supplies to a managed session, in the layout a terminfo library reads. The release manifest lists
//! both, so its signature covers them.
//!
//! They are the statement of what the release ships. A worker still writes its own copy of the
//! database when a session starts, from its own engine, and nothing reads the tree's.
//!
//! Neither file is typed in a second place. The manifest is made from the checkout's fixtures by
//! the engine's own table, and the database by the engine's own compiler; a tree whose copy differs
//! from what this checkout makes is refused before a manifest exists to be signed.

use std::path::{Path, PathBuf};

use kr_term::capability;

use crate::refusal::{Refusal, Result, read, refuse};

/// Where a release keeps the terminal's capability manifest.
pub const CAPABILITIES: &str = "share/terminal-capabilities.json";

/// Where a release keeps the terminfo database, with the layout a library reads below it.
pub const TERMINFO: &str = "share/terminfo";

fn fixtures(checkout: &Path) -> PathBuf {
    checkout.join("fixtures/terminal")
}

/// The manifest this checkout makes of its fixtures, as the text a tree carries. Refused when the
/// checkout's own committed manifest is not that text, or a fixture belongs to no category.
fn made(checkout: &Path) -> Result<String> {
    let directory = fixtures(checkout);
    let unowned = capability::unowned(&directory).map_err(Refusal)?;
    if let Some(file) = unowned.first() {
        refuse!(
            "fixtures/terminal/{file} is owned by no category of the terminal capability manifest"
        );
    }
    let manifest = capability::manifest(&directory).map_err(Refusal)?;
    let text = capability::render(&manifest);
    let committed = read(&directory.join(capability::FILE))?;
    if committed != text.as_bytes() {
        refuse!(
            "fixtures/terminal/{} is not what the fixtures make: `kr-term-fixtures` writes it \
             again",
            capability::FILE
        );
    }
    Ok(text)
}

fn compiled() -> Result<Vec<u8>> {
    kr_term::terminfo::compiled()
        .map_err(|error| Refusal(format!("the terminfo database does not compile: {error}")))
}

/// Writes the capability manifest and the terminfo database into a tree.
///
/// # Errors
///
/// Returns a refusal when the checkout's manifest is not current, or a file cannot be written.
pub fn write(tree: &Path, checkout: &Path) -> Result<()> {
    let text = made(checkout)?;
    let path = tree.join(CAPABILITIES);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| Refusal(format!("{} cannot be made: {error}", parent.display())))?;
    }
    std::fs::write(&path, text)
        .map_err(|error| Refusal(format!("{} cannot be written: {error}", path.display())))?;
    let root = tree.join(TERMINFO);
    kr_term::terminfo::write_database(&root)
        .map_err(|error| Refusal(format!("{} cannot be written: {error}", root.display())))
}

/// Holds what a tree carries of the terminal to what its checkout now makes.
///
/// # Errors
///
/// Returns a refusal naming the first file the tree lacks or carries changed.
pub fn held(tree: &Path, checkout: &Path) -> Result<()> {
    let manifest = made(checkout)?;
    let carried = read(&tree.join(CAPABILITIES))
        .map_err(|_| Refusal(format!("the tree carries no {CAPABILITIES}")))?;
    if carried != manifest.as_bytes() {
        refuse!("{CAPABILITIES} is not the manifest this checkout makes of its fixtures");
    }
    let database = compiled()?;
    // Where the engine itself puts the entry, one file for each name a library looks for it by.
    let root = tree.join(TERMINFO);
    for path in kr_term::terminfo::Description::pinned().entry_paths(&root) {
        let shown = path
            .strip_prefix(tree)
            .unwrap_or(&path)
            .display()
            .to_string();
        let carried = read(&path).map_err(|_| Refusal(format!("the tree carries no {shown}")))?;
        if carried != database {
            refuse!("{shown} is not the database this checkout compiles");
        }
    }
    Ok(())
}
