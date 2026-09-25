//! The documentation's side of the method registry.
//!
//! A reader who meets a method on the wire has to be able to find it in `docs/`. The check here
//! reads the registry and every Markdown document under the documentation root, and names each
//! method that no document mentions.

use std::path::{Path, PathBuf};

use kr_protocol::method::REGISTRY;

/// Returns every Markdown document under `root`, in path order.
///
/// Symbolic links are not followed: a document is a file in the tree.
pub(crate) fn markdown_documents(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "md")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Returns true when `text` names `name` as a whole method name.
///
/// `session.read` inside `session.read_own`, or `pair.status` inside a longer dotted name, is not
/// a mention of it. A full stop that ends a sentence is.
pub(crate) fn names(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let continues = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    text.match_indices(name).any(|(start, _)| {
        let end = start + name.len();
        let opens = start == 0 || !(continues(bytes[start - 1]) || bytes[start - 1] == b'.');
        let closes = match bytes.get(end) {
            None => true,
            Some(&b'.') => !bytes.get(end + 1).copied().is_some_and(continues),
            Some(&byte) => !continues(byte),
        };
        opens && closes
    })
}

/// Returns the registry methods that no Markdown document under `docs` names, in registry order.
pub(crate) fn unnamed_methods(docs: &Path) -> std::io::Result<Vec<&'static str>> {
    let mut texts = Vec::new();
    for document in markdown_documents(docs)? {
        texts.push(std::fs::read_to_string(&document)?);
    }
    Ok(REGISTRY
        .iter()
        .map(|entry| entry.name)
        .filter(|name| !texts.iter().any(|text| names(text, name)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::names;

    #[test]
    fn a_name_is_found_only_as_a_whole_method_name() {
        assert!(names("call `session.read` first", "session.read"));
        assert!(names("session.read", "session.read"));
        assert!(names("it answers session.read.", "session.read"));
        assert!(!names("`session.read_own`", "session.read"));
        assert!(!names("`xsession.read`", "session.read"));
        assert!(!names("`plugin.session.read`", "session.read"));
        assert!(!names("`session.read.page`", "session.read"));
    }
}
