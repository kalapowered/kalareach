//! The worker's own files: what the worker may change in the run's tree while a daemon runs or does
//! not, each by the row of its kind. A row says which names it covers and what may happen to them;
//! a change to a name no row covers is refused by the compare.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::compare::{Class, Layout, Refusal};
use crate::run::RootPin;
use crate::tree::{Change, Entry, Kind, Record, prefix_digest};

/// The name of the conversation claims directory, directly below the state root.
const CLAIMS: &str = "conversation-claims-1";

/// The name of the directory of the output-time indexes, directly below the state directory.
const OUTPUT_TIMES: &str = "output-times";

/// The names that may stand beside an index `<session>.sqlite`: what a SQLite connection makes and
/// what the worker makes while it builds a new index.
const BESIDE_THE_INDEX: [&str; 5] = ["-wal", "-shm", "-journal", ".new", ".new-journal"];

/// The letter every session root's name begins with, before its hexadecimal digits.
const SESSION_ROOT_PREFIX: &str = "c";

/// The name of a session spool's boundary file.
const BOUNDARY_FILE: &str = "boundary";

/// The name of the file the boundary is written to before it is renamed over the boundary file.
const BOUNDARY_STAGING: &str = "boundary.writing";

/// Where the compare reads bytes the record does not hold, through the run's handles.
#[derive(Clone, Copy, Debug)]
pub struct Place<'a> {
    /// The run's directory.
    pub root: &'a Path,
    /// The directory `root` was pinned as.
    pub pin: &'a RootPin,
}

/// What the rows of the worker's files found.
#[derive(Debug, Default)]
pub struct Judged {
    /// The changes no row allows.
    pub refusals: Vec<Refusal>,
    /// What the rows allowed and keep as evidence.
    pub notes: Vec<String>,
}

fn is_session_root(name: &str) -> bool {
    name.strip_prefix(SESSION_ROOT_PREFIX)
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_diagnostics(name: &str) -> bool {
    name.starts_with("kr-worker-") && name.ends_with(".diagnostics")
}

/// The name of `path` where `path` is a direct child of `directory`.
fn child_of<'a>(path: &'a Path, directory: &Path) -> Option<&'a str> {
    if path.parent()? != directory {
        return None;
    }
    path.file_name()?.to_str()
}

/// The first component of `path` below `directory`.
fn first_below<'a>(path: &'a Path, directory: &Path) -> Option<&'a str> {
    path.strip_prefix(directory)
        .ok()?
        .components()
        .next()?
        .as_os_str()
        .to_str()
}

/// Whether a row of the worker's files covers `path`.
#[must_use]
pub fn covers(layout: &Layout, path: &Path) -> bool {
    path.starts_with(layout.state_dir.join("spool"))
        || path.starts_with(layout.state_root.join(CLAIMS))
        || first_below(path, &layout.runtime_dir).is_some_and(is_session_root)
        || child_of(path, &layout.state_dir.join("sessions"))
            .is_some_and(|name| name.starts_with("session-"))
        || child_of(path, &layout.state_dir.join("jobs")).is_some_and(is_diagnostics)
        || path.starts_with(layout.state_dir.join(OUTPUT_TIMES))
}

/// The cursor a spool segment's name gives: twenty digits and `.out`.
fn cursor_of(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".out")?;
    if digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()) {
        digits.parse().ok()
    } else {
        None
    }
}

/// The value of a decimal text.
fn decimal(entry: &Entry) -> Option<u64> {
    let text = std::str::from_utf8(entry.content.as_ref()?).ok()?.trim();
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// The segments of the spool directory `directory` in `record`, oldest first.
fn segments(record: &Record, directory: &Path) -> Vec<(u64, PathBuf, Entry)> {
    let mut found: Vec<(u64, PathBuf, Entry)> = record
        .entries()
        .filter(|(path, _)| path.parent() == Some(directory))
        .filter_map(|(path, entry)| {
            let cursor = cursor_of(path.file_name()?.to_str()?)?;
            (entry.kind == Kind::File).then(|| (cursor, path.to_path_buf(), entry.clone()))
        })
        .collect();
    found.sort_by_key(|(cursor, _, _)| *cursor);
    found
}

struct Judge<'a> {
    layout: &'a Layout,
    place: Place<'a>,
    base: &'a Record,
    now: &'a Record,
    uid: u32,
    changes: BTreeMap<PathBuf, Vec<Change>>,
    judged: Judged,
}

/// Judges the changes between `base` and `now` that a row of the worker's files covers.
#[must_use]
pub fn judge(layout: &Layout, place: Place<'_>, base: &Record, now: &Record, uid: u32) -> Judged {
    let mut changes: BTreeMap<PathBuf, Vec<Change>> = BTreeMap::new();
    for change in base.changes_to(now) {
        if covers(layout, change.path()) {
            changes
                .entry(change.path().to_path_buf())
                .or_default()
                .push(change);
        }
    }
    let mut judge = Judge {
        layout,
        place,
        base,
        now,
        uid,
        changes,
        judged: Judged::default(),
    };
    let paths: Vec<PathBuf> = judge.changes.keys().cloned().collect();
    for path in &paths {
        judge.entry(path);
    }
    judge.spool_directories();
    judge.judged
}

impl Judge<'_> {
    fn refuse(&mut self, path: &Path, why: &str) {
        self.refuse_as(Class::Rule, path, why);
    }

    /// Refuses `path` as an entry that no row of the worker's files names.
    fn refuse_unknown(&mut self, path: &Path, why: &str) {
        self.refuse_as(Class::UnknownEntry, path, why);
    }

    fn refuse_as(&mut self, class: Class, path: &Path, why: &str) {
        let lines: Vec<String> = self.changes.get(path).map_or_else(Vec::new, |all| {
            all.iter().map(ToString::to_string).collect()
        });
        self.judged.refusals.push(Refusal {
            path: path.to_path_buf(),
            said: format!("{}; {why}", lines.join("; ")),
            class,
        });
    }

    fn changes_at(&self, path: &Path) -> Vec<Change> {
        self.changes.get(path).cloned().unwrap_or_default()
    }

    /// What was added at `path`, if the entry is new.
    fn added(&self, path: &Path) -> Option<Entry> {
        self.changes_at(path)
            .into_iter()
            .find_map(|change| match change {
                Change::Added { now, .. } => Some(now),
                _ => None,
            })
    }

    /// Whether the entry at `path` that the record holds was changed in any way but its bytes.
    fn object_changed(&self, path: &Path) -> bool {
        self.changes_at(path)
            .iter()
            .any(|change| !matches!(change, Change::Bytes { .. } | Change::Added { .. }))
    }

    fn entry(&mut self, path: &Path) {
        let layout = self.layout;
        let spool = layout.state_dir.join("spool");
        let claims = layout.state_root.join(CLAIMS);
        if let Ok(rest) = path.strip_prefix(&spool) {
            self.spool_entry(path, rest);
        } else if let Ok(rest) = path.strip_prefix(&claims) {
            self.claim(path, rest);
        } else if first_below(path, &layout.runtime_dir).is_some() {
            self.session_root(path);
        } else if let Ok(rest) = path.strip_prefix(layout.state_dir.join(OUTPUT_TIMES)) {
            self.output_times(path, rest);
        } else if child_of(path, &layout.state_dir.join("jobs")).is_some() {
            self.diagnostics(path);
        } else {
            self.journal(path);
        }
    }

    /// Whether the recorded spool entry at `path` changed in a way its writer does not need: its
    /// kind, its link target, its owner or its permission bits, or, for a segment, its object. The
    /// boundary file and its staging file may be other objects, since the writer renames the staging
    /// file over the boundary file.
    fn spool_object_changed(&self, path: &Path, is_segment: bool) -> bool {
        self.changes_at(path).iter().any(|change| match change {
            Change::Retyped { .. }
            | Change::Target { .. }
            | Change::Owner { .. }
            | Change::Mode { .. } => true,
            Change::Replaced { .. } => is_segment,
            Change::Added { .. } | Change::Gone { .. } | Change::Bytes { .. } => false,
        })
    }

    fn spool_entry(&mut self, path: &Path, rest: &Path) {
        const W0: &str = "the spool keeps the directory it is and the session directories the \
                          record holds, and holds no other directory";
        const W1: &str = "a session's spool holds segments, a boundary file and its staging file, \
                          and this entry is none of them";
        const W6: &str = "the spool's host-cap lock is a regular file, and a recorded one keeps \
                          its object";
        const W7: &str = "a recorded spool segment keeps its object, its kind, its owner and its \
                          permission bits";
        const W8: &str = "a recorded boundary file and its staging file keep their kind, their \
                          owner and their permission bits; the writer may put other files in their \
                          places, since it renames the staging file over the boundary file";
        let names: Vec<&str> = rest
            .components()
            .filter_map(|part| part.as_os_str().to_str())
            .collect();
        match names.as_slice() {
            [] => self.refuse_unknown(path, W0),
            ["host-cap.lock"] => {
                let new_and_not_a_file = self.added(path).is_some_and(|now| now.kind != Kind::File);
                if new_and_not_a_file || self.object_changed(path) {
                    self.refuse(path, W6);
                }
            }
            [_] => self.refuse_unknown(path, W0),
            [_, name] => {
                let segment = cursor_of(name).is_some();
                let known = segment || *name == BOUNDARY_FILE || *name == BOUNDARY_STAGING;
                let new_and_not_a_file = self.added(path).is_some_and(|now| now.kind != Kind::File);
                if !known || new_and_not_a_file {
                    self.refuse_unknown(path, W1);
                } else if self.spool_object_changed(path, segment) {
                    self.refuse(path, if segment { W7 } else { W8 });
                }
            }
            _ => self.refuse_unknown(path, W1),
        }
    }

    /// The rules that look at the segments of a spool directory as a list.
    fn spool_directories(&mut self) {
        const W2: &str = "spool segments go from the oldest end only, and every segment but the \
                          newest recorded one keeps its bytes";
        const W3: &str = "the newest recorded spool segment may only grow: its recorded bytes must \
                          be the start of its bytes now";
        const W4: &str =
            "a new spool segment starts at or after where the newest recorded one ends now";
        const W5: &str = "the spool's boundary is decimal text and not below the recorded value";
        let spool = self.layout.state_dir.join("spool");
        let directories: Vec<PathBuf> = self
            .base
            .entries()
            .filter(|(path, entry)| {
                entry.kind == Kind::Directory
                    && path.parent() == Some(spool.as_path())
                    && self
                        .now
                        .get(path)
                        .is_some_and(|now| now.kind == Kind::Directory)
            })
            .map(|(path, _)| path.to_path_buf())
            .collect();
        for directory in directories {
            let original = segments(self.base, &directory);
            let current = segments(self.now, &directory);
            // Where the newest recorded segment ends now: a new segment follows what it holds.
            let end_of_newest = original.last().map(|(cursor, path, entry)| {
                cursor.saturating_add(self.now.get(path).map_or(entry.size, |now| now.size))
            });
            // A failed write cuts the newest segment back and removes it when it is empty.
            let newest_gone_empty = original
                .last()
                .is_some_and(|(_, path, entry)| entry.size == 0 && self.now.get(path).is_none());
            let recorded = &original[..original.len() - usize::from(newest_gone_empty)];
            let present: Vec<bool> = recorded
                .iter()
                .map(|(_, path, _)| self.now.get(path).is_some())
                .collect();
            if let Some(first) = present.iter().position(|kept| *kept)
                && let Some(gap) = present[first..].iter().position(|kept| !*kept)
            {
                let path = recorded[first + gap].1.clone();
                self.refuse(&path, W2);
            }
            for (index, (_, path, entry)) in recorded.iter().enumerate() {
                let Some(now) = self.now.get(path) else {
                    continue;
                };
                let newest = index + 1 == recorded.len() && !newest_gone_empty;
                if !newest && (now.size, now.digest) != (entry.size, entry.digest) {
                    self.refuse(path, W2);
                } else if newest && (now.size, now.digest) != (entry.size, entry.digest) {
                    let held = prefix_digest(self.place.root, self.place.pin, path, entry.size);
                    if !matches!(held, Ok(Some(digest)) if Some(digest) == entry.digest) {
                        self.refuse(path, W3);
                    }
                }
            }
            for (cursor, path, _) in &current {
                if self.base.get(path).is_none() && end_of_newest.is_some_and(|end| *cursor < end) {
                    self.refuse(path, W4);
                }
            }
            let boundary = directory.join(BOUNDARY_FILE);
            if self.changes.contains_key(&boundary) {
                let (was, now) = (self.base.get(&boundary), self.now.get(&boundary));
                let fine = match (was, now) {
                    (_, None) => was.is_none(),
                    (None, Some(now)) => decimal(now).is_some(),
                    (Some(was), Some(now)) => {
                        decimal(now).is_some_and(|now| now >= decimal(was).unwrap_or(0))
                    }
                };
                if !fine {
                    self.refuse(&boundary, W5);
                }
            }
        }
    }

    fn claim(&mut self, path: &Path, rest: &Path) {
        const W8: &str = "the conversation claims directory is new, owner-only and directly below \
                          the state root, and holds only empty owner-only files named by 64 \
                          hexadecimal digits and .lock";
        const W9: &str = "a recorded conversation claim keeps its object, its owner, its mode and \
                          its emptiness";
        let uid = self.uid;
        let names: Vec<&str> = rest
            .components()
            .filter_map(|part| part.as_os_str().to_str())
            .collect();
        let added = self.added(path);
        let recorded_changed = self
            .changes_at(path)
            .iter()
            .any(|change| !matches!(change, Change::Added { .. }));
        if recorded_changed {
            self.refuse(path, W9);
            return;
        }
        let Some(now) = added else { return };
        let fine = match names.as_slice() {
            [] => now.kind == Kind::Directory && now.owner == uid && now.mode & 0o777 == 0o700,
            [name] => {
                now.kind == Kind::File
                    && now.size == 0
                    && now.owner == uid
                    && now.mode & 0o077 == 0
                    && name.strip_suffix(".lock").is_some_and(|digits| {
                        digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            }
            _ => false,
        };
        if !fine {
            self.refuse(path, W8);
        }
    }

    fn session_root(&mut self, path: &Path) {
        const W10: &str = "a new session root is an owner-only directory of the account directly in \
                           the runtime directory, and what is added inside it is a file, a \
                           directory or a socket of the account, never a link";
        const W11: &str = "an entry of a session root that the record holds may not change";
        let uid = self.uid;
        let at_the_root = path.parent() == Some(self.layout.runtime_dir.as_path());
        if self
            .changes_at(path)
            .iter()
            .any(|change| !matches!(change, Change::Added { .. }))
        {
            self.refuse(path, W11);
            return;
        }
        let Some(now) = self.added(path) else { return };
        let fine = if at_the_root {
            now.kind == Kind::Directory && now.owner == uid && now.mode & 0o777 == 0o700
        } else {
            matches!(now.kind, Kind::File | Kind::Directory | Kind::Socket) && now.owner == uid
        };
        if !fine {
            self.refuse(path, W10);
        }
    }

    fn diagnostics(&mut self, path: &Path) {
        const W12: &str = "a worker's diagnostics file must be recorded, and keeps its object, its \
                           owner and its mode and only grows: its recorded bytes must be the start \
                           of its bytes now";
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        if !is_diagnostics(name) {
            return;
        }
        let object_changed = self.object_changed(path);
        if self.added(path).is_some() || object_changed {
            self.refuse(path, W12);
            return;
        }
        let (Some(was), Some(now)) = (self.base.get(path), self.now.get(path)) else {
            return;
        };
        let held = prefix_digest(self.place.root, self.place.pin, path, was.size);
        if now.size < was.size || !matches!(held, Ok(Some(digest)) if Some(digest) == was.digest) {
            self.refuse(path, W12);
        } else if now.size > was.size {
            self.judged.notes.push(format!(
                "{}: {} bytes were added to the worker's diagnostics",
                path.display(),
                now.size - was.size
            ));
        }
    }

    fn output_times(&mut self, path: &Path, rest: &Path) {
        const W15: &str = "the output-times directory is new, owner-only and directly below the \
                           state directory; the index keeps its object, its owner and its mode; \
                           beside it only a -wal, a -shm, a -journal, a .new and a .new-journal \
                           may stand, each a file of the account that others may not read or write";
        let uid = self.uid;
        let names: Vec<&str> = rest
            .components()
            .filter_map(|part| part.as_os_str().to_str())
            .collect();
        let now = self.added(path);
        let mut unknown = false;
        let fine = match names.as_slice() {
            [] => {
                let only_added = self
                    .changes_at(path)
                    .iter()
                    .all(|change| matches!(change, Change::Added { .. }));
                only_added
                    && now.is_none_or(|now| {
                        now.kind == Kind::Directory && now.owner == uid && now.mode & 0o777 == 0o700
                    })
            }
            [name] if name.ends_with(".sqlite") => {
                !self.object_changed(path)
                    && now.is_none_or(|now| now.kind == Kind::File && now.owner == uid)
            }
            [name]
                if BESIDE_THE_INDEX.iter().any(|suffix| {
                    name.strip_suffix(suffix)
                        .is_some_and(|index| index.ends_with(".sqlite"))
                }) =>
            {
                let retyped_or_moved = self.changes_at(path).iter().any(|change| {
                    matches!(
                        change,
                        Change::Retyped { .. } | Change::Owner { .. } | Change::Mode { .. }
                    )
                });
                !retyped_or_moved
                    && now.is_none_or(|now| {
                        now.kind == Kind::File && now.owner == uid && now.mode & 0o077 == 0
                    })
            }
            _ => {
                unknown = true;
                false
            }
        };
        if !fine {
            let class = if unknown {
                Class::UnknownEntry
            } else {
                Class::Rule
            };
            self.refuse_as(class, path, W15);
        }
    }

    fn journal(&mut self, path: &Path) {
        const W13: &str = "a session journal keeps its object, its owner and its mode; its bytes \
                           are not compared";
        const W14: &str = "beside a session journal only a -wal and a -shm may stand, each a file \
                           of the account that others may not read or write";
        let uid = self.uid;
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        let main = name
            .strip_suffix("-wal")
            .or_else(|| name.strip_suffix("-shm"));
        match main {
            None if name.ends_with(".sqlite") => {
                if self.added(path).is_some() || self.object_changed(path) {
                    self.refuse(path, W13);
                }
            }
            Some(main) if main.ends_with(".sqlite") => {
                let main_path = path.with_file_name(main);
                let beside_a_journal =
                    self.base.get(&main_path).is_some() || self.now.get(&main_path).is_some();
                let new_and_wrong = self.added(path).is_some_and(|now| {
                    now.kind != Kind::File || now.owner != uid || now.mode & 0o077 != 0
                });
                let retyped_or_moved = self.changes_at(path).iter().any(|change| {
                    matches!(
                        change,
                        Change::Retyped { .. } | Change::Owner { .. } | Change::Mode { .. }
                    )
                });
                if !beside_a_journal {
                    self.refuse_unknown(path, W14);
                } else if new_and_wrong || retyped_or_moved {
                    self.refuse(path, W14);
                }
            }
            _ => self.refuse_unknown(path, W14),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    use crate::compare::Interval;
    use crate::compare::tests::{World, world};

    const KILL: Interval = Interval::AtTheKill { restarted: false };
    const ATTEMPT: Interval = Interval::BeforeTheAttempt;

    /// What the compare refuses and notes for a tree set up by `setup` and then changed by `act`:
    /// the same at a kill and before the attempt, since the worker's files do not wait for either.
    fn outcome(
        name: &str,
        setup: impl Fn(&World),
        act: impl Fn(&World),
    ) -> (Vec<String>, Vec<String>) {
        let world = world(name);
        setup(&world);
        let before = world.record();
        act(&world);
        let (refused, notes) = world.compared(&before, KILL);
        assert_eq!(
            world.compared(&before, ATTEMPT),
            (refused.clone(), notes.clone()),
            "{name}: the same at both intervals"
        );
        world.clean();
        (refused, notes)
    }

    /// Expects that `outcome` refuses once, saying `why`.
    fn refused_by(name: &str, why: &str, setup: impl Fn(&World), act: impl Fn(&World)) {
        let (refused, _) = outcome(name, setup, act);
        assert!(
            refused.len() == 1 && refused[0].ends_with(why),
            "{name}: one refusal that ends {why:?}: {refused:#?}"
        );
    }

    /// Expects that `outcome` refuses nothing.
    fn allowed(name: &str, setup: impl Fn(&World), act: impl Fn(&World)) {
        let (refused, _) = outcome(name, setup, act);
        assert_eq!(refused, Vec::<String>::new(), "{name}");
    }

    fn segment(world: &World, cursor: u64) -> std::path::PathBuf {
        world.state(&format!("spool/s1.log/{cursor:020}.out"))
    }

    /// A spool of three segments: 10, 10 and 5 bytes, from the cursors 0, 10 and 20.
    fn spool(world: &World) {
        world.put(&segment(world, 0), b"0123456789");
        world.put(&segment(world, 10), b"abcdefghij");
        world.put(&segment(world, 20), b"vwxyz");
    }

    const W2: &str = "spool segments go from the oldest end only, and every segment but the newest \
                      recorded one keeps its bytes";
    const W3: &str = "the newest recorded spool segment may only grow: its recorded bytes must be \
                      the start of its bytes now";
    const W4: &str =
        "a new spool segment starts at or after where the newest recorded one ends now";
    const W5: &str = "the spool's boundary is decimal text and not below the recorded value";

    /// Retention removes the oldest segments, the last segment grows and new segments follow it:
    /// none is refused.
    #[test]
    fn the_spool_may_lose_its_oldest_segments_and_grow_at_its_end() {
        allowed("oldest", spool, |w| {
            std::fs::remove_file(segment(w, 0)).expect("removed");
        });
        allowed("two-oldest", spool, |w| {
            std::fs::remove_file(segment(w, 0)).expect("removed");
            std::fs::remove_file(segment(w, 10)).expect("removed");
        });
        allowed("last-grows", spool, |w| {
            std::fs::write(segment(w, 20), b"vwxyz and more").expect("grown");
        });
        allowed("new-segment", spool, |w| {
            w.put(&segment(w, 25), b"new");
            w.put(&segment(w, 400), b"later");
        });
        allowed("removal-and-growth", spool, |w| {
            std::fs::remove_file(segment(w, 0)).expect("removed");
            std::fs::write(segment(w, 20), b"vwxyz!").expect("grown");
            w.put(&segment(w, 30), b"new");
        });
        // The newest recorded segment was empty and a failed write removed it.
        let empty_newest = |w: &World| {
            w.put(&segment(w, 0), b"0123456789");
            w.put(&segment(w, 10), b"");
        };
        allowed("empty-newest-gone", empty_newest, |w| {
            std::fs::remove_file(segment(w, 10)).expect("removed");
        });
        allowed("empty-newest-and-oldest-gone", empty_newest, |w| {
            std::fs::remove_file(segment(w, 10)).expect("removed");
            std::fs::remove_file(segment(w, 0)).expect("removed");
        });
    }

    /// A middle segment removed, a sealed segment changed or grown, the newest changed in its start
    /// or cut short, a new segment that starts early, and a newest segment that was not empty and
    /// is gone, are each refused.
    #[test]
    fn a_spool_that_loses_a_middle_segment_or_changes_a_sealed_one_is_refused() {
        refused_by("middle", W2, spool, |w| {
            std::fs::remove_file(segment(w, 10)).expect("removed");
        });
        refused_by("sealed-grown", W2, spool, |w| {
            std::fs::write(segment(w, 10), b"abcdefghij and more").expect("grown");
        });
        refused_by("sealed-changed", W2, spool, |w| {
            std::fs::write(segment(w, 0), b"0123456780").expect("changed");
        });
        refused_by("newest-start", W3, spool, |w| {
            std::fs::write(segment(w, 20), b"VWXYZ and more").expect("changed");
        });
        refused_by("newest-cut", W3, spool, |w| {
            std::fs::write(segment(w, 20), b"vw").expect("cut");
        });
        refused_by("early-segment", W4, spool, |w| {
            w.put(&segment(w, 24), b"early");
        });
        refused_by("newest-gone", W2, spool, |w| {
            std::fs::remove_file(segment(w, 20)).expect("removed");
        });
        // With the empty newest gone, the segment before it is sealed.
        let (refused, _) = outcome(
            "sealed-before-empty-newest",
            |w| {
                w.put(&segment(w, 0), b"0123456789");
                w.put(&segment(w, 10), b"");
            },
            |w| {
                std::fs::remove_file(segment(w, 10)).expect("removed");
                std::fs::write(segment(w, 0), b"0123456789 and more").expect("grown");
            },
        );
        assert!(
            refused.len() == 1 && refused[0].ends_with(W2),
            "{refused:#?}"
        );
    }

    /// The boundary may rise or appear as decimal text, and is refused lowered, gone or not decimal.
    #[test]
    fn the_spool_boundary_may_only_rise_as_decimal_text() {
        let boundary = |w: &World| w.state("spool/s1.log/boundary");
        let with_boundary = |w: &World| {
            spool(w);
            w.put(&boundary(w), b"50");
        };
        allowed("rises", with_boundary, |w| {
            std::fs::write(boundary(w), b"60").expect("written");
        });
        allowed("appears", spool, |w| w.put(&boundary(w), b"60"));
        allowed("staging", with_boundary, |w| {
            w.put(&w.state("spool/s1.log/boundary.writing"), b"61");
        });
        refused_by("lowered", W5, with_boundary, |w| {
            std::fs::write(boundary(w), b"49").expect("written");
        });
        refused_by("text", W5, with_boundary, |w| {
            std::fs::write(boundary(w), b"5x").expect("written");
        });
        refused_by("gone", W5, with_boundary, |w| {
            std::fs::remove_file(boundary(w)).expect("removed");
        });
        refused_by("new-text", W5, spool, |w| w.put(&boundary(w), b"-1"));
    }

    /// The host-cap lock may appear and change; a recorded one that is replaced or gone, a name no
    /// row knows, a directory among the segments, a new session's spool and a replaced spool
    /// directory are refused.
    #[test]
    fn the_host_cap_lock_and_the_names_of_the_spool_are_kept() {
        const W6: &str = "the spool's host-cap lock is a regular file, and a recorded one keeps its \
                          object";
        const W1: &str = "a session's spool holds segments, a boundary file and its staging file, \
                          and this entry is none of them";
        const W0: &str = "the spool keeps the directory it is and the session directories the \
                          record holds, and holds no other directory";
        let lock = |w: &World| w.state("spool/host-cap.lock");
        allowed("lock-appears", spool, |w| w.put(&lock(w), b""));
        allowed(
            "lock-written",
            |w| {
                spool(w);
                w.put(&lock(w), b"");
            },
            |w| std::fs::write(lock(w), b"held").expect("written"),
        );
        let with_lock = |w: &World| {
            spool(w);
            w.put(&lock(w), b"");
        };
        refused_by("lock-replaced", W6, with_lock, |w| w.replace(&lock(w), b""));
        refused_by("lock-gone", W6, with_lock, |w| {
            std::fs::remove_file(lock(w)).expect("removed");
        });
        refused_by("lock-a-directory", W6, spool, |w| {
            std::fs::create_dir_all(lock(w)).expect("a directory");
        });
        refused_by("unknown-name", W1, spool, |w| {
            w.put(&w.state("spool/s1.log/other"), b"x");
        });
        refused_by("segment-a-directory", W1, spool, |w| {
            std::fs::create_dir_all(segment(w, 30)).expect("a directory");
        });
        refused_by("new-session-spool", W0, spool, |w| {
            w.put(&w.state("spool/s2.log/00000000000000000000.out"), b"x");
        });
        let replaced = outcome("spool-replaced", spool, |w| {
            std::fs::rename(w.state("spool/s1.log"), w.state("spool/moved")).expect("moved");
            std::fs::create_dir_all(w.state("spool/s1.log")).expect("another directory");
        });
        assert!(
            replaced.0.iter().any(|line| line.ends_with(W0)),
            "{:#?}",
            replaced.0
        );
    }

    const W7: &str = "a recorded spool segment keeps its object, its kind, its owner and its \
                      permission bits";
    const W8: &str = "a recorded boundary file and its staging file keep their kind, their owner \
                      and their permission bits; the writer may put other files in their places, \
                      since it renames the staging file over the boundary file";

    /// A recorded segment, boundary file or staging file that changes its permission bits or its
    /// kind, a recorded segment that is another object with the same bytes, and a recorded name no
    /// row knows that changes are each refused. The boundary file and its staging file may be other
    /// objects, and a new segment may start where the newest recorded one ends now.
    #[test]
    fn a_recorded_spool_entry_keeps_its_kind_and_its_mode_and_a_segment_keeps_its_object() {
        const W1: &str = "a session's spool holds segments, a boundary file and its staging file, \
                          and this entry is none of them";
        let boundary = |w: &World| w.state("spool/s1.log/boundary");
        let staging = |w: &World| w.state("spool/s1.log/boundary.writing");
        let with_both = |w: &World| {
            spool(w);
            w.put(&boundary(w), b"50");
            w.put(&staging(w), b"51");
        };
        let chmod = |path: std::path::PathBuf| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("mode");
        };
        refused_by("sealed-chmod", W7, spool, |w| chmod(segment(w, 0)));
        refused_by("newest-chmod", W7, spool, |w| chmod(segment(w, 20)));
        refused_by("sealed-same-bytes-other-object", W7, spool, |w| {
            w.replace(&segment(w, 0), b"0123456789");
        });
        refused_by("newest-same-bytes-other-object", W7, spool, |w| {
            w.replace(&segment(w, 20), b"vwxyz");
        });
        refused_by("boundary-chmod", W8, with_both, |w| chmod(boundary(w)));
        refused_by("staging-chmod", W8, with_both, |w| chmod(staging(w)));
        refused_by("staging-a-link", W8, with_both, |w| {
            std::fs::remove_file(staging(w)).expect("removed");
            std::os::unix::fs::symlink("elsewhere", staging(w)).expect("a link");
        });
        // The boundary file as a link is refused by its own row and by the rule of its text.
        let (refused, _) = outcome("boundary-a-link", with_both, |w| {
            std::fs::remove_file(boundary(w)).expect("removed");
            std::os::unix::fs::symlink("elsewhere", boundary(w)).expect("a link");
        });
        assert!(
            refused.len() == 2
                && refused.iter().any(|line| line.ends_with(W8))
                && refused.iter().any(|line| line.ends_with(W5)),
            "a boundary file made a link is refused by W8 and W5: {refused:#?}"
        );
        refused_by(
            "unknown-recorded-name",
            W1,
            |w| {
                spool(w);
                w.put(&w.state("spool/s1.log/other"), b"x");
            },
            |w| chmod(w.state("spool/s1.log/other")),
        );
        // What the writer does: the staging file is made and renamed over the boundary file, and
        // a recorded staging file is made again.
        allowed("boundary-another-object", with_both, |w| {
            w.replace(&boundary(w), b"50");
        });
        allowed("staging-another-object", with_both, |w| {
            w.replace(&staging(w), b"61");
        });
        allowed("staging-gone", with_both, |w| {
            std::fs::remove_file(staging(w)).expect("removed");
        });
        // A new segment follows the newest one as it is now: it grew to 14 bytes, so it ends at 34.
        let grown = |w: &World| std::fs::write(segment(w, 20), b"vwxyz and more").expect("grown");
        refused_by("new-segment-inside-the-grown-newest", W4, spool, |w| {
            grown(w);
            w.put(&segment(w, 25), b"new");
        });
        refused_by("new-segment-one-byte-early", W4, spool, |w| {
            grown(w);
            w.put(&segment(w, 33), b"new");
        });
        allowed("new-segment-at-the-grown-end", spool, |w| {
            grown(w);
            w.put(&segment(w, 34), b"new");
        });
    }

    fn claim_name() -> String {
        format!("{}.lock", "4b".repeat(32))
    }

    /// A new claims directory and a new empty owner-only claim are not refused; a claim that is not
    /// empty, not owner-only or wrongly named, a directory that is not owner-only, and a recorded
    /// claim that is replaced, written or gone are.
    #[test]
    fn the_conversation_claims_may_be_made_and_a_recorded_claim_keeps_its_object() {
        const W8: &str = "the conversation claims directory is new, owner-only and directly below \
                          the state root, and holds only empty owner-only files named by 64 \
                          hexadecimal digits and .lock";
        const W9: &str = "a recorded conversation claim keeps its object, its owner, its mode and \
                          its emptiness";
        let directory = |w: &World| w.root.join("s/conversation-claims-1");
        let claim = |w: &World| directory(w).join(claim_name());
        let make = |w: &World| {
            std::fs::create_dir_all(directory(w)).expect("a directory");
            std::fs::set_permissions(directory(w), std::fs::Permissions::from_mode(0o700))
                .expect("owner only");
        };
        let with_directory = make;
        let with_claim = |w: &World| {
            make(w);
            w.put(&claim(w), b"");
        };
        allowed(
            "new-directory-and-claim",
            |_| {},
            |w| {
                make(w);
                w.put(&claim(w), b"");
            },
        );
        allowed("new-claim", with_directory, |w| w.put(&claim(w), b""));
        refused_by("not-empty", W8, with_directory, |w| w.put(&claim(w), b"x"));
        refused_by("wrong-name", W8, with_directory, |w| {
            w.put(&directory(w).join("claim.lock"), b"");
        });
        refused_by("not-owner-only", W8, with_directory, |w| {
            w.put(&claim(w), b"");
            std::fs::set_permissions(claim(w), std::fs::Permissions::from_mode(0o644))
                .expect("readable");
        });
        refused_by(
            "directory-not-owner-only",
            W8,
            |_| {},
            |w| {
                std::fs::create_dir_all(directory(w)).expect("a directory");
                std::fs::set_permissions(directory(w), std::fs::Permissions::from_mode(0o755))
                    .expect("open");
            },
        );
        refused_by("replaced", W9, with_claim, |w| w.replace(&claim(w), b""));
        refused_by("written", W9, with_claim, |w| {
            std::fs::write(claim(w), b"held").expect("written");
        });
        refused_by("gone", W9, with_claim, |w| {
            std::fs::remove_file(claim(w)).expect("removed");
        });
    }

    /// A new session root with its files and a socket is not refused; a link in it, a root that is
    /// not owner-only or not a directory, and a recorded entry that changed or is gone are; a name
    /// that is no session root's is covered by no row.
    #[test]
    fn a_session_root_may_be_made_and_what_it_holds_may_not_change() {
        const W10: &str = "a new session root is an owner-only directory of the account directly \
                           in the runtime directory, and what is added inside it is a file, a \
                           directory or a socket of the account, never a link";
        const W11: &str = "an entry of a session root that the record holds may not change";
        let root = |w: &World| w.runtime("cd545");
        let inner = |w: &World| root(w).join("5132");
        let make = |w: &World| {
            std::fs::create_dir_all(inner(w)).expect("a session root");
            for directory in [root(w), inner(w)] {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                    .expect("owner only");
            }
        };
        let populated = |w: &World| {
            make(w);
            w.put(&inner(w).join("launch"), b"launch");
        };
        let socket = std::sync::Mutex::new(None);
        allowed(
            "new-root",
            |_| {},
            |w| {
                populated(w);
                w.put(&inner(w).join("credential"), b"credential");
                *socket.lock().expect("lock") =
                    Some(UnixListener::bind(inner(w).join("gw.sock")).expect("a socket"));
            },
        );
        allowed("new-name-in-a-recorded-root", populated, |w| {
            w.put(&inner(w).join("registration.1.2"), b"registration");
        });
        refused_by("link", W10, populated, |w| {
            std::os::unix::fs::symlink("/etc", inner(w).join("link")).expect("a link");
        });
        refused_by(
            "root-not-owner-only",
            W10,
            |_| {},
            |w| {
                make(w);
                std::fs::set_permissions(root(w), std::fs::Permissions::from_mode(0o755))
                    .expect("open");
            },
        );
        refused_by("root-a-file", W10, |_| {}, |w| w.put(&root(w), b"a file"));
        refused_by("changed", W11, populated, |w| {
            std::fs::write(inner(w).join("launch"), b"changed").expect("written");
        });
        refused_by("gone", W11, populated, |w| {
            std::fs::remove_file(inner(w).join("launch")).expect("removed");
        });
        refused_by("replaced", W11, populated, |w| {
            w.replace(&inner(w).join("launch"), b"launch");
        });
        // A directory that is no session root is no row's.
        let (refused, _) = outcome(
            "no-root",
            |_| {},
            |w| {
                w.put(&w.runtime("x1/file"), b"x");
            },
        );
        assert!(
            refused
                .iter()
                .all(|line| line.ends_with("no row of the live daemon's files covers this entry")),
            "{refused:#?}"
        );
        assert_eq!(refused.len(), 2, "{refused:#?}");
    }

    /// A diagnostics file only grows, with a note of how much; a truncated, rewritten, replaced,
    /// unrecorded or chmodded one is refused.
    #[test]
    fn a_diagnostics_file_only_grows_and_must_be_recorded() {
        const W12: &str = "a worker's diagnostics file must be recorded, and keeps its object, its \
                           owner and its mode and only grows: its recorded bytes must be the start \
                           of its bytes now";
        let file = |w: &World| w.state("jobs/kr-worker-r1.diagnostics");
        let recorded = |w: &World| w.put(&file(w), b"kr-worker: one\n");
        let (refused, notes) = outcome("grows", recorded, |w| {
            std::fs::write(file(w), b"kr-worker: one\nkr-worker: two\n").expect("grown");
        });
        assert_eq!(refused, Vec::<String>::new());
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert!(
            notes[0].ends_with("15 bytes were added to the worker's diagnostics"),
            "{notes:#?}"
        );
        let (_, notes) = outcome("unchanged", recorded, |_| {});
        assert_eq!(notes, Vec::<String>::new());
        refused_by("truncated", W12, recorded, |w| {
            std::fs::write(file(w), b"kr-worker").expect("cut");
        });
        refused_by("rewritten", W12, recorded, |w| {
            std::fs::write(file(w), b"kr-worker: ONE\nmore\n").expect("rewritten");
        });
        refused_by("replaced", W12, recorded, |w| {
            w.replace(&file(w), b"kr-worker: one\nmore\n");
        });
        refused_by("unrecorded", W12, |_| {}, |w| recorded(w));
        refused_by("chmod", W12, recorded, |w| {
            std::fs::set_permissions(file(w), std::fs::Permissions::from_mode(0o644))
                .expect("readable");
        });
    }

    /// A session journal's main file may change in place and its `-wal` and `-shm` may be made,
    /// changed, replaced and removed; a replaced or removed main file, a sidecar that is readable by
    /// others, a `-journal`, a `-wal` with no journal and a new main file are refused.
    #[test]
    fn a_session_journal_keeps_its_object_and_its_sidecars_come_and_go() {
        const W13: &str = "a session journal keeps its object, its owner and its mode; its bytes \
                           are not compared";
        const W14: &str = "beside a session journal only a -wal and a -shm may stand, each a file \
                           of the account that others may not read or write";
        let journal = |w: &World| w.state("sessions/session-a1.sqlite");
        let beside =
            |w: &World, suffix: &str| w.state(&format!("sessions/session-a1.sqlite{suffix}"));
        let recorded = |w: &World| {
            w.put(&journal(w), b"journal");
            w.put(&beside(w, "-wal"), b"wal");
            w.put(&beside(w, "-shm"), b"shm");
        };
        allowed("main-written", recorded, |w| {
            std::fs::write(journal(w), b"journal, written").expect("written");
        });
        allowed("sidecars", recorded, |w| {
            std::fs::write(beside(w, "-wal"), b"wal, written").expect("written");
            w.replace(&beside(w, "-shm"), b"another shm");
        });
        allowed("sidecars-removed", recorded, |w| {
            std::fs::remove_file(beside(w, "-wal")).expect("removed");
            std::fs::remove_file(beside(w, "-shm")).expect("removed");
        });
        allowed(
            "sidecars-made",
            |w| w.put(&journal(w), b"journal"),
            |w| {
                w.put(&beside(w, "-wal"), b"wal");
                w.put(&beside(w, "-shm"), b"shm");
            },
        );
        refused_by("main-replaced", W13, recorded, |w| {
            w.replace(&journal(w), b"journal")
        });
        refused_by("main-removed", W13, recorded, |w| {
            std::fs::remove_file(journal(w)).expect("removed");
        });
        refused_by("new-main", W13, |_| {}, |w| w.put(&journal(w), b"journal"));
        refused_by(
            "readable-sidecar",
            W14,
            |w| w.put(&journal(w), b"journal"),
            |w| {
                w.put(&beside(w, "-wal"), b"wal");
                std::fs::set_permissions(beside(w, "-wal"), std::fs::Permissions::from_mode(0o644))
                    .expect("readable");
            },
        );
        refused_by("rollback-journal", W14, recorded, |w| {
            w.put(&beside(w, "-journal"), b"journal");
        });
        refused_by(
            "no-journal",
            W14,
            |_| {},
            |w| w.put(&beside(w, "-wal"), b"wal"),
        );
    }

    const W15: &str = "the output-times directory is new, owner-only and directly below the state \
                       directory; the index keeps its object, its owner and its mode; beside it \
                       only a -wal, a -shm, a -journal, a .new and a .new-journal may stand, each a \
                       file of the account that others may not read or write";

    fn index(world: &World) -> std::path::PathBuf {
        world.state("output-times/s1.sqlite")
    }

    fn beside_the_index(world: &World, suffix: &str) -> std::path::PathBuf {
        world.state(&format!("output-times/s1.sqlite{suffix}"))
    }

    fn without_the_directory(world: &World) {
        std::fs::remove_dir(world.state("output-times")).expect("an empty directory");
    }

    fn with_an_index(world: &World) {
        world.put(&index(world), b"index");
        world.put(&beside_the_index(world, "-wal"), b"wal");
        world.put(&beside_the_index(world, "-shm"), b"shm");
    }

    /// The index may be written in place or built where it was absent, and the names beside it may
    /// be made, changed, replaced and removed; a new owner-only directory is not refused.
    #[test]
    fn the_output_time_index_may_be_written_and_the_names_beside_it_come_and_go() {
        allowed("written", with_an_index, |w| {
            std::fs::write(index(w), b"index, written").expect("written");
        });
        allowed("sidecars", with_an_index, |w| {
            std::fs::write(beside_the_index(w, "-wal"), b"wal, written").expect("written");
            w.replace(&beside_the_index(w, "-shm"), b"another shm");
        });
        allowed("sidecars-removed", with_an_index, |w| {
            std::fs::remove_file(beside_the_index(w, "-wal")).expect("removed");
            std::fs::remove_file(beside_the_index(w, "-shm")).expect("removed");
        });
        allowed(
            "names-made",
            |w| w.put(&index(w), b"index"),
            |w| {
                for suffix in ["-wal", "-shm", "-journal", ".new", ".new-journal"] {
                    w.put(&beside_the_index(w, suffix), b"x");
                }
            },
        );
        allowed(
            "build-files-removed",
            |w| {
                w.put(&index(w), b"index");
                w.put(&beside_the_index(w, ".new"), b"x");
                w.put(&beside_the_index(w, ".new-journal"), b"x");
            },
            |w| {
                std::fs::remove_file(beside_the_index(w, ".new")).expect("removed");
                std::fs::remove_file(beside_the_index(w, ".new-journal")).expect("removed");
            },
        );
        allowed(
            "index-built",
            |w| w.put(&beside_the_index(w, ".new"), b"x"),
            |w| {
                std::fs::rename(beside_the_index(w, ".new"), index(w)).expect("built");
            },
        );
        allowed("new-directory", without_the_directory, |w| {
            std::fs::create_dir_all(w.state("output-times")).expect("a directory");
            std::fs::set_permissions(
                w.state("output-times"),
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("owner only");
            with_an_index(w);
        });
    }

    /// The index replaced by a copy on a new inode, removed, retyped or changed in its mode, a name
    /// beside it that no row knows, a sidecar that others may read, a link, a name below another
    /// directory, and a directory that is not owner-only or changed its mode are each refused.
    #[test]
    fn a_replaced_index_and_a_name_no_row_knows_are_refused() {
        refused_by("index-replaced", W15, with_an_index, |w| {
            w.replace(&index(w), b"index");
        });
        refused_by("index-removed", W15, with_an_index, |w| {
            std::fs::remove_file(index(w)).expect("removed");
        });
        refused_by("index-mode", W15, with_an_index, |w| {
            std::fs::set_permissions(index(w), std::fs::Permissions::from_mode(0o644))
                .expect("readable");
        });
        refused_by("index-retyped", W15, with_an_index, |w| {
            std::fs::remove_file(index(w)).expect("removed");
            std::fs::create_dir_all(index(w)).expect("a directory");
        });
        refused_by("unknown-name", W15, with_an_index, |w| {
            w.put(&beside_the_index(w, ".other"), b"x");
        });
        refused_by("no-index-name", W15, with_an_index, |w| {
            w.put(&w.state("output-times/s1-wal"), b"x");
        });
        refused_by("readable-sidecar", W15, with_an_index, |w| {
            w.put(&beside_the_index(w, "-journal"), b"x");
            std::fs::set_permissions(
                beside_the_index(w, "-journal"),
                std::fs::Permissions::from_mode(0o644),
            )
            .expect("readable");
        });
        refused_by("sidecar-a-link", W15, with_an_index, |w| {
            std::os::unix::fs::symlink("/etc", beside_the_index(w, ".new")).expect("a link");
        });
        refused_by("sidecar-chmod", W15, with_an_index, |w| {
            std::fs::set_permissions(
                beside_the_index(w, "-wal"),
                std::fs::Permissions::from_mode(0o644),
            )
            .expect("readable");
        });
        refused_by("directory-mode", W15, with_an_index, |w| {
            std::fs::set_permissions(
                w.state("output-times"),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("open");
        });
        let (refused, _) = outcome("below-another-directory", with_an_index, |w| {
            w.put(&w.state("output-times/more/s1.sqlite"), b"x");
        });
        assert_eq!(refused.len(), 2, "{refused:#?}");
        assert!(
            refused.iter().all(|line| line.ends_with(W15)),
            "{refused:#?}"
        );
        refused_by(
            "directory-not-owner-only",
            W15,
            without_the_directory,
            |w| {
                std::fs::create_dir_all(w.state("output-times")).expect("a directory");
                std::fs::set_permissions(
                    w.state("output-times"),
                    std::fs::Permissions::from_mode(0o755),
                )
                .expect("open");
            },
        );
    }
}
