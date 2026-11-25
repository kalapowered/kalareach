//! The admission of a held tree: what the broker asks of every object of a tree before it grants
//! the tree to an invocation.
//!
//! The grant gives an invocation's group modify rights on every object of the tree, so a tree is
//! admitted only where nothing outside the invocation can already reach it. Each object's
//! descriptor is read from the object's own handle, and the platform's access check is asked for
//! each right alone, for the probe token of each boundary account (a sibling invocation), for the
//! person's own token and for the broker's own. A right that a sibling holds refuses the tree and
//! names the object and the right; a right that the person or the broker lacks, and that the grant
//! needs, refuses it too, before anything is changed. A read right that a shared group holds is
//! reported, not refused.

use crate::frame::Class;
use crate::frame::invocation::{MAX_DETAIL_BYTES, RefusedKind};
use crate::manifest::Manifest;
use crate::refusal::Refusal;

use super::client::ClientIdentity;
use super::hold::{FOLDER_CHANGED_WORDS, RULE_FOLDER_CHANGED, TreeHold};
use super::rights::{
    ImpersonationToken, ObjectKind, PERSON_RIGHTS, REPORT_RIGHT, Right, SYSTEM_RIGHTS, Sd, may,
    probe_token, system_may, write_rights,
};
use super::walk::{DirHandle, Entry, INSPECT, Kind, Lost, ROOT_BOUNDS, Verdict, walk};

/// The most notes admission keeps; the rest are counted.
pub const MAX_NOTES: usize = 64;

/// The rule of a refusal for a right that a boundary account holds on an object.
pub const RULE_SIBLING: &str = "admission-sibling-right";
/// The rule of a refusal for a right that the person's own account lacks on an object.
pub const RULE_PERSON_LACKS: &str = "admission-person-right";
/// The rule of a refusal for a right that the broker's own account lacks on an object.
pub const RULE_SYSTEM_LACKS: &str = "admission-broker-right";
/// The rule of a refusal for an object that the broker cannot open.
pub const RULE_OPEN: &str = "admission-open";
/// The rule of a refusal for a link in the tree.
pub const RULE_LINK: &str = "admission-link";
/// The rule of a refusal for a check that could not be made.
pub const RULE_FAILED: &str = "admission-failed";

/// The end of the reply when a boundary account holds a right on an object; the path and the right
/// come before it.
// text: SIBLING_WORDS
pub const SIBLING_WORDS: &str = "another boundary account has this right";

/// The end of the reply when the person's own account lacks a right that the grant needs.
// text: PERSON_LACKS_WORDS
pub const PERSON_LACKS_WORDS: &str = "your account does not have this right";

/// The end of the reply when the broker's own account lacks a right that the grant needs.
// text: SYSTEM_LACKS_WORDS
pub const SYSTEM_LACKS_WORDS: &str = "the broker does not have this right";

/// The end of the reply when the broker cannot open an object of the tree; the path comes before it.
// text: OPEN_WORDS
pub const OPEN_WORDS: &str = "the broker cannot open this object";

/// The end of the reply when an object of the tree is a link; the path comes before it.
// text: LINK_WORDS
pub const LINK_WORDS: &str = "this object is a link, and the broker does not follow links";

/// The start of the reply when a check could not be made; the platform's error follows after a
/// colon.
// text: ADMISSION_FAILED_WORDS
pub const ADMISSION_FAILED_WORDS: &str =
    "the broker could not check the access lists of the project";

/// The rights a sibling must not hold on an ancestor of the tree: delete what is in it, delete it,
/// change its list and change its owner. The right to add to an ancestor is not one of them.
const ANCESTOR_RIGHTS: [Right; 4] = [
    Right::DeleteChild,
    Right::Delete,
    Right::WriteDac,
    Right::WriteOwner,
];

/// What admission found that does not refuse the tree.
#[derive(Debug, Default)]
pub struct Admitted {
    /// A note for each object that a shared group can read, `shared-read: <path>`, at most
    /// [`MAX_NOTES`].
    pub notes: Vec<String>,
    /// How many notes were left out beyond the bound.
    pub notes_cut: u32,
}

/// The probe tokens of the two boundary accounts, which stand for the sibling invocations of each
/// class.
#[derive(Debug)]
pub struct Probes {
    checkout: ImpersonationToken,
    connect: ImpersonationToken,
}

impl Probes {
    /// Makes the probe token of each class from the accounts the manifest records.
    ///
    /// # Errors
    ///
    /// Refuses when a class has no account or its token cannot be made.
    pub fn new(manifest: &Manifest) -> Result<Probes, Refusal> {
        Ok(Probes {
            checkout: probe_of(manifest, Class::Checkout)?,
            connect: probe_of(manifest, Class::Connect)?,
        })
    }

    fn both(&self) -> [&ImpersonationToken; 2] {
        [&self.checkout, &self.connect]
    }
}

fn probe_of(manifest: &Manifest, class: Class) -> Result<ImpersonationToken, Refusal> {
    probe_token(manifest, class).map_err(|failure| failed(&failure))
}

fn failed(failure: &dyn std::fmt::Display) -> Refusal {
    Refusal::new(
        RefusedKind::Admission,
        RULE_FAILED,
        &format!("{ADMISSION_FAILED_WORDS}: {failure}"),
    )
}

/// The right in words.
fn right_words(right: Right) -> &'static str {
    match right {
        Right::ReadData => "list or read",
        Right::WriteData => "write data or add a file",
        Right::AppendData => "append data or add a folder",
        Right::WriteEa => "write extended attributes",
        Right::DeleteChild => "delete what is in the folder",
        Right::WriteAttributes => "write attributes",
        Right::Delete => "delete",
        Right::ReadControl => "read the access list",
        Right::WriteDac => "change the access list",
        Right::WriteOwner => "change the owner",
    }
}

/// The reply's detail: the path, then the end, which is cut at its start with `...` when the whole
/// would be longer than a detail may be, so that the end is never the part that is lost.
fn fitted(path: &str, end: &str) -> String {
    let room = MAX_DETAIL_BYTES.saturating_sub(end.len());
    if path.len() <= room {
        return format!("{path}{end}");
    }
    let mut start = path.len() - room.saturating_sub(3);
    while !path.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}{end}", &path[start..])
}

fn right_refusal(rule: &'static str, path: &str, right: Right, words: &str) -> Refusal {
    Refusal::new(
        RefusedKind::Admission,
        rule,
        &fitted(path, &format!(", {}: {words}", right_words(right))),
    )
}

fn object_refusal(rule: &'static str, path: &str, words: &str) -> Refusal {
    Refusal::new(
        RefusedKind::Admission,
        rule,
        &fitted(path, &format!(": {words}")),
    )
}

/// The path of the tree as the person spelled it, without the platform's long-path prefix.
fn spelled(path: &str) -> &str {
    path.strip_prefix(r"\\?\").unwrap_or(path)
}

/// The path of each directory of the chain, the volume's root first, from the tree's own path.
fn chain_paths(tree_path: &str) -> Vec<String> {
    let parts: Vec<&str> = spelled(tree_path).split('\\').collect();
    (0..parts.len())
        .map(|index| {
            if index == 0 {
                format!("{}\\", parts[0])
            } else {
                parts[..=index].join("\\")
            }
        })
        .collect()
}

struct Checking<'a> {
    client: &'a ClientIdentity,
    probes: &'a Probes,
    admitted: Admitted,
}

impl Checking<'_> {
    /// Refuses when a probe token holds one of the rights on the descriptor, each right alone.
    fn siblings(&self, path: &str, descriptor: &Sd, rights: &[Right]) -> Result<(), Refusal> {
        for right in rights {
            for probe in self.probes.both() {
                if may(probe, descriptor, *right) {
                    return Err(right_refusal(RULE_SIBLING, path, *right, SIBLING_WORDS));
                }
            }
        }
        Ok(())
    }

    /// Every check an object of the grant's walk meets, in order: the siblings' write rights, what
    /// the person needs, what the broker needs, and then the note for a read right that is shared.
    fn object(&mut self, path: &str, kind: ObjectKind, descriptor: &Sd) -> Result<(), Refusal> {
        self.siblings(path, descriptor, write_rights(kind))?;
        for right in PERSON_RIGHTS {
            if !self.client.may(descriptor, right) {
                return Err(right_refusal(
                    RULE_PERSON_LACKS,
                    path,
                    right,
                    PERSON_LACKS_WORDS,
                ));
            }
        }
        for right in SYSTEM_RIGHTS {
            if !system_may(descriptor, right) {
                return Err(right_refusal(
                    RULE_SYSTEM_LACKS,
                    path,
                    right,
                    SYSTEM_LACKS_WORDS,
                ));
            }
        }
        if self
            .probes
            .both()
            .into_iter()
            .any(|probe| may(probe, descriptor, REPORT_RIGHT))
        {
            if self.admitted.notes.len() < MAX_NOTES {
                self.admitted.notes.push(format!("shared-read: {path}"));
            } else {
                self.admitted.notes_cut += 1;
            }
        }
        Ok(())
    }

    /// The ancestors of the tree, from the volume's root: nothing a sibling holds may let it delete
    /// what is in an ancestor, or the ancestor, or change its list or its owner.
    fn ancestors(&self, hold: &TreeHold) -> Result<(), Refusal> {
        let paths = chain_paths(&hold.path);
        let above = hold.chain.len().saturating_sub(1);
        for (index, directory) in hold.chain.iter().take(above).enumerate() {
            let descriptor =
                Sd::of_handle(directory.handle()).map_err(|failure| failed(&failure))?;
            let path = paths.get(index).map_or("", String::as_str);
            self.siblings(path, &descriptor, &ANCESTOR_RIGHTS)?;
        }
        Ok(())
    }

    /// The tree's root, and then every object below it.
    fn tree(&mut self, hold: &TreeHold) -> Result<(), Refusal> {
        let Some(root) = hold.chain.last() else {
            return Err(Refusal::new(
                RefusedKind::Admission,
                RULE_FOLDER_CHANGED,
                FOLDER_CHANGED_WORDS,
            ));
        };
        let descriptor = Sd::of_handle(root.handle()).map_err(|failure| failed(&failure))?;
        self.object(spelled(&hold.path), ObjectKind::Directory, &descriptor)?;
        let mut refusal: Option<Refusal> = None;
        let outcome = walk(root, ROOT_BOUNDS, &mut |entry: &Entry<'_>| {
            if refusal.is_some() {
                return Ok(Verdict::Skip);
            }
            if let Err(found) = self.visit(hold, root, entry) {
                refusal = Some(found);
                return Ok(Verdict::Skip);
            }
            Ok(Verdict::Descend)
        });
        if let Some(found) = refusal {
            return Err(found);
        }
        match outcome {
            Ok(report) if report.problems.is_empty() => Ok(()),
            Ok(_) => Err(Refusal::new(
                RefusedKind::Admission,
                RULE_FOLDER_CHANGED,
                FOLDER_CHANGED_WORDS,
            )),
            Err(other) => Err(failed(&other)),
        }
    }

    fn visit(
        &mut self,
        hold: &TreeHold,
        root: &DirHandle,
        entry: &Entry<'_>,
    ) -> Result<(), Refusal> {
        let path = path_of(hold, root, entry);
        let opened = match entry.open(INSPECT) {
            Ok(Ok(opened)) => opened,
            Ok(Err(Lost::Refused(_))) => return Err(object_refusal(RULE_OPEN, &path, OPEN_WORDS)),
            Ok(Err(Lost::Gone | Lost::IdentityChanged | Lost::MovedOut)) => {
                return Err(Refusal::new(
                    RefusedKind::Admission,
                    RULE_FOLDER_CHANGED,
                    FOLDER_CHANGED_WORDS,
                ));
            }
            Err(failure) => return Err(failed(&failure)),
        };
        let kind = match opened.kind {
            Kind::File => ObjectKind::File,
            Kind::Directory => ObjectKind::Directory,
            Kind::ReparsePoint => return Err(object_refusal(RULE_LINK, &path, LINK_WORDS)),
        };
        let descriptor = Sd::of_handle(&opened.handle).map_err(|failure| failed(&failure))?;
        self.object(&path, kind, &descriptor)
    }
}

/// The path of an object of the walk as the person spelled the tree's: the tree's path, then what
/// lies between the tree's root and the object's directory, then the object's name.
fn path_of(hold: &TreeHold, root: &DirHandle, entry: &Entry<'_>) -> String {
    let directory = entry.dir.path();
    let below = directory.get(root.path().len()..).unwrap_or(&[]);
    format!(
        "{}{}\\{}",
        spelled(&hold.path),
        String::from_utf16_lossy(below),
        entry.child.display()
    )
}

/// Admits the held tree or refuses it, naming the object and the right.
///
/// # Errors
///
/// Refuses when a boundary account holds a write right on an ancestor of the tree or on an object
/// of it, when the person or the broker lacks a right the grant needs, when an object cannot be
/// opened or is a link, or when a check cannot be made.
pub fn admit(
    hold: &TreeHold,
    client: &ClientIdentity,
    probes: &Probes,
) -> Result<Admitted, Refusal> {
    let mut checking = Checking {
        client,
        probes,
        admitted: Admitted::default(),
    };
    checking.ancestors(hold)?;
    checking.tree(hold)?;
    Ok(checking.admitted)
}
