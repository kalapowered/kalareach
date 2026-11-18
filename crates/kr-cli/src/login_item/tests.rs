//! Unit cases of the login item's steps, records and renderers.
//!
//! Every case works on explicit paths in one private directory and reads no environment variable,
//! so none can reach a real home. A case runs a step list up to a step and stops, and compares the
//! tree it leaves with what the record says is under way; the step lists are the product's own.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use kr_client::shown::Shown;
use kr_ipc::testing::PrivateTempDir;

use super::record::{self, Operation, Pending, Record};
use super::render::{self, Kind, Parts};
use super::steps::{self, Event, Mode, PUBLISH, PUT_BACK, REMOVE, Run, Settled, Tail};

const LABEL: &str = "kr-desktop-host-x";
const OLD: &str = "old bytes\n";
const NEW: &str = "new bytes\n";

struct Tree {
    dir: PrivateTempDir,
    kind: Kind,
}

impl Tree {
    fn new() -> Self {
        let dir = PrivateTempDir::create();
        std::fs::create_dir(dir.path().join("state")).expect("a state directory");
        Self {
            dir,
            kind: Kind::current(),
        }
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn directory(&self) -> PathBuf {
        self.dir.path().join("home").join(self.kind.directory())
    }

    fn file(&self) -> PathBuf {
        self.directory()
            .join(format!("{LABEL}.{}", self.kind.extension()))
    }

    fn run(&self, new: &str, before: Option<Record>) -> Run {
        let file = self.file();
        let paths = steps::Paths {
            record: record::path(&self.state()),
            aside: record::beside(&file, "kr-moving"),
            staging: record::beside(&file, "kr-staging"),
            file,
        };
        Run::new(paths, self.kind, LABEL, new, before)
    }

    fn record(&self) -> Option<Record> {
        record::read(&self.state(), self.kind, LABEL, &Shown::said("the record"))
            .unwrap_or_else(|why| panic!("the record is usable: {why}"))
    }

    /// A tree where a whole publication of `OLD` was made.
    fn published() -> (Self, Run) {
        let tree = Self::new();
        let mut run = tree.run(OLD, None);
        steps::run_all(&mut run, &PUBLISH).unwrap_or_else(|_| panic!("the publication runs"));
        (tree, run)
    }

    /// A tree where a publication of `NEW` stopped after `steps` of its list.
    fn publishing(steps_done: usize) -> Self {
        let tree = Self::new();
        let mut run = tree.run(NEW, None);
        steps::run_all(&mut run, &PUBLISH[..steps_done])
            .unwrap_or_else(|_| panic!("the steps run"));
        tree
    }

    /// A tree where a removal of the file holding `OLD` stopped after `steps_done` steps.
    fn removing(steps_done: usize) -> Self {
        let (tree, _) = Self::published();
        let mut run = tree.run("", tree.record());
        steps::run_all(&mut run, &REMOVE[..steps_done]).unwrap_or_else(|_| panic!("the steps run"));
        tree
    }

    /// The paths the record's pending step names, as a run that finishes it holds them.
    fn finishing(&self) -> (Run, Record) {
        let record = self.record().expect("a record");
        (self.run("", Some(record.clone())), record)
    }

    fn entries(&self, directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn leftovers(&self) -> Vec<String> {
        self.entries(&self.directory())
            .into_iter()
            .filter(|name| name.starts_with('.'))
            .collect()
    }
}

fn bytes(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

fn staging_of(record: &Record) -> Option<PathBuf> {
    record.pending.as_ref().and_then(|p| p.staging.clone())
}

fn aside_of(record: &Record) -> Option<PathBuf> {
    record.pending.as_ref().and_then(|p| p.aside.clone())
}

fn write_owner_only(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).expect("a file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("a mode");
}

fn same(a: &Path, b: &Path) -> bool {
    let (a, b) = (
        std::fs::symlink_metadata(a).expect("a"),
        std::fs::symlink_metadata(b).expect("b"),
    );
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[test]
fn a_publish_stopped_after_each_step_leaves_the_state_its_row_names() {
    for done in 1..=6 {
        let tree = Tree::publishing(done);
        let file = tree.file();
        let record = tree.record().expect("a record is there after every step");
        assert_eq!(record.contents, NEW, "after step {done}");
        match done {
            1 | 2 => {
                assert_eq!(bytes(&file), None, "after step {done}");
                let staging = staging_of(&record).expect("names the staging file first");
                assert!(!staging.exists(), "after step {done}");
                assert_eq!(
                    tree.directory().exists(),
                    done == 2,
                    "the directory is made by step 2"
                );
                assert_eq!(
                    record.pending.as_ref().map(|p| p.operation),
                    Some(Operation::Publish)
                );
            }
            3 => {
                assert_eq!(bytes(&file), None);
                let staging = staging_of(&record).expect("named");
                assert_eq!(bytes(&staging).as_deref(), Some(NEW.as_bytes()));
                let mode = std::fs::metadata(&staging)
                    .expect("staged")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "the staging file is owner-only");
            }
            4 => {
                let staging = staging_of(&record).expect("named");
                assert_eq!(bytes(&file).as_deref(), Some(NEW.as_bytes()));
                assert!(same(&file, &staging), "one file under two names");
            }
            5 => {
                let staging = staging_of(&record).expect("still named");
                assert_eq!(bytes(&file).as_deref(), Some(NEW.as_bytes()));
                assert!(!staging.exists());
                assert!(record.pending.is_some());
            }
            _ => {
                assert_eq!(bytes(&file).as_deref(), Some(NEW.as_bytes()));
                assert!(record.pending.is_none());
            }
        }
    }
    let (tree, _) = Tree::published();
    assert_eq!(tree.leftovers(), Vec::<String>::new());
    assert_eq!(
        tree.entries(&tree.state()),
        vec![super::RECORD_FILE.to_owned()],
        "a whole publication leaves the file and the record"
    );
    assert!(tree.record().expect("a record").pending.is_none());
}

#[test]
fn a_removal_stopped_after_each_step_leaves_the_state_its_row_names() {
    for done in 1..=5 {
        let tree = Tree::removing(done);
        let file = tree.file();
        match done {
            1 => {
                let record = tree.record().expect("a record");
                let aside = aside_of(&record).expect("the record names the aside first");
                assert_eq!(
                    bytes(&file).as_deref(),
                    Some(OLD.as_bytes()),
                    "not moved yet"
                );
                assert!(!aside.exists());
                assert_eq!(
                    record.pending.as_ref().map(|p| p.operation),
                    Some(Operation::Remove)
                );
            }
            2 => {
                let record = tree.record().expect("a record");
                let aside = aside_of(&record).expect("named");
                assert_eq!(bytes(&file), None);
                assert_eq!(bytes(&aside).as_deref(), Some(OLD.as_bytes()));
            }
            3 | 4 => {
                let record = tree.record().expect("the record is dropped last");
                assert_eq!(bytes(&file), None);
                assert!(!aside_of(&record).expect("named").exists(), "step {done}");
            }
            _ => {
                assert!(tree.record().is_none());
                assert_eq!(tree.leftovers(), Vec::<String>::new());
            }
        }
    }
}

#[test]
fn a_file_put_back_and_stopped_between_its_two_steps_leaves_one_file_under_two_names() {
    let tree = Tree::removing(2);
    let record = tree.record().expect("a record");
    let aside = aside_of(&record).expect("named");
    let (mut run, _) = tree.finishing();
    run.paths.aside.clone_from(&aside);
    steps::run_all(&mut run, &PUT_BACK[..1]).unwrap_or_else(|_| panic!("links back"));
    assert!(same(&tree.file(), &aside), "one file under two names");
    assert_eq!(
        aside_of(&tree.record().expect("a record")),
        Some(aside),
        "the record still names the aside"
    );
}

/// A tree for each stopped state of the publish and remove lists, with what its row says an
/// install and a remove end with.
fn every_stopped_state() -> Vec<(String, Tree)> {
    let mut states = Vec::new();
    for done in 1..=5 {
        states.push((format!("publish {done}"), Tree::publishing(done)));
    }
    for done in 1..=4 {
        states.push((format!("remove {done}"), Tree::removing(done)));
    }
    let tree = Tree::removing(2);
    let (mut run, record) = tree.finishing();
    run.paths.aside = aside_of(&record).expect("named");
    steps::run_all(&mut run, &PUT_BACK[..1]).unwrap_or_else(|_| panic!("links back"));
    states.push(("put back 1".to_owned(), tree));
    states
}

fn read_bytes_of_tree(tree: &Tree) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut all = Vec::new();
    for directory in [tree.state(), tree.directory()] {
        for name in tree.entries(&directory) {
            let path = directory.join(name);
            all.push((path.clone(), bytes(&path)));
        }
    }
    all
}

#[test]
fn settle_finishes_each_stopped_state_the_way_its_row_says() {
    // Reading never settles: no byte of the tree changes.
    for (name, tree) in every_stopped_state() {
        let before = read_bytes_of_tree(&tree);
        let _ = tree.record();
        assert!(
            before == read_bytes_of_tree(&tree),
            "{name}: reading changes nothing"
        );
    }
    // An install finishes each state: nothing under way, no leftover, a record that agrees.
    for (name, tree) in every_stopped_state() {
        let (mut run, record) = tree.finishing();
        let settled = steps::settle(&mut run, &record, Mode::Install)
            .unwrap_or_else(|_| panic!("{name}: settles"));
        assert!(settled == Settled::Done, "{name}");
        let after = tree.record().expect("a record");
        assert!(after.pending.is_none(), "{name}: nothing is under way");
        assert_eq!(tree.leftovers(), Vec::<String>::new(), "{name}");
        let file = bytes(&tree.file());
        let wants_new = name.starts_with("publish");
        assert_eq!(after.contents, if wants_new { NEW } else { OLD }, "{name}");
        if name == "publish 4" || name == "publish 5" || name.starts_with("remove 1") {
            assert_eq!(file.as_deref(), Some(after.contents.as_bytes()), "{name}");
        }
    }
    // A removal finishes each state: no file, no leftover and no record.
    for (name, tree) in every_stopped_state() {
        let (mut run, record) = tree.finishing();
        steps::settle(&mut run, &record, Mode::Remove)
            .unwrap_or_else(|_| panic!("{name}: settles"));
        let clean = tree.record().expect("a clean record");
        let mut run = tree.run("", Some(clean));
        steps::run_all(&mut run, &REMOVE).unwrap_or_else(|_| panic!("{name}: removes"));
        assert_eq!(bytes(&tree.file()), None, "{name}");
        assert!(tree.record().is_none(), "{name}");
        assert_eq!(tree.leftovers(), Vec::<String>::new(), "{name}");
    }
}

#[test]
fn a_failed_step_is_taken_back_or_left_named_by_what_is_on_disk() {
    // A directory stands at the staging name: the staging fails, the directory stays untouched and
    // named, and the record stays naming it.
    let tree = Tree::new();
    let mut run = tree.run(NEW, None);
    std::fs::create_dir_all(tree.directory()).expect("a directory");
    std::fs::create_dir(&run.paths.staging).expect("a directory at the staging name");
    let staging = run.paths.staging.clone();
    let error = steps::run_all(&mut run, &PUBLISH).expect_err("the staging fails");
    let failure = steps::fail(&mut run, Operation::Publish, error);
    assert!(matches!(failure.tail, Tail::KeptNamed(ref path) if *path == staging));
    assert!(staging.is_dir(), "the directory is untouched");
    assert_eq!(
        staging_of(&tree.record().expect("the record stays")),
        Some(staging)
    );
    assert_eq!(bytes(&tree.file()), None, "no file was written");

    // A file stands where the directory belongs: the record is taken back and nothing is left.
    let tree = Tree::new();
    std::fs::create_dir_all(tree.dir.path().join("home")).expect("a home");
    std::fs::write(tree.directory(), b"a file").expect("a file where the directory belongs");
    let mut run = tree.run(NEW, None);
    let error = steps::run_all(&mut run, &PUBLISH).expect_err("the directory fails");
    let failure = steps::fail(&mut run, Operation::Publish, error);
    assert!(matches!(failure.tail, Tail::TookBack));
    assert!(tree.record().is_none(), "no record");
    assert_eq!(bytes(&tree.directory()).as_deref(), Some(&b"a file"[..]));

    // The same failure with a record already there puts that record back as it was.
    let (tree, _) = Tree::published();
    std::fs::remove_file(tree.file()).expect("the file goes");
    std::fs::remove_dir(tree.directory()).expect("the directory goes");
    std::fs::write(tree.directory(), b"a file").expect("a file where the directory belongs");
    let before = tree.record();
    let mut run = tree.run(OLD, before.clone());
    let error = steps::run_all(&mut run, &PUBLISH).expect_err("the directory fails");
    let failure = steps::fail(&mut run, Operation::Publish, error);
    assert!(matches!(failure.tail, Tail::TookBack));
    assert!(tree.record() == before, "the record is as it was");
}

#[test]
fn a_file_that_is_not_vouched_is_never_touched_by_settle_and_its_leftovers_are_named() {
    for other in ["bytes", "directory", "link"] {
        for stopped in ["publish", "remove"] {
            let tree = if stopped == "publish" {
                Tree::publishing(4)
            } else {
                Tree::removing(2)
            };
            let file = tree.file();
            let _ = std::fs::remove_file(&file);
            match other {
                "bytes" => write_owner_only(&file, b"somebody else's\n", 0o600),
                "directory" => std::fs::create_dir(&file).expect("a directory"),
                _ => std::os::unix::fs::symlink(tree.dir.path(), &file).expect("a link"),
            }
            let before = read_bytes_of_tree(&tree);
            let (mut run, record) = tree.finishing();
            let settled = steps::settle(&mut run, &record, Mode::Install)
                .unwrap_or_else(|_| panic!("{stopped} {other}: settles"));
            assert!(
                settled == Settled::Changed,
                "{stopped} {other}: install refuses"
            );
            assert!(
                before == read_bytes_of_tree(&tree),
                "{stopped} {other}: nothing changed"
            );
            // A removal takes out what is vouched, leaves the file, names it and drops the record.
            let (mut run, record) = tree.finishing();
            steps::settle(&mut run, &record, Mode::Remove)
                .unwrap_or_else(|_| panic!("{stopped} {other}: settles for removal"));
            let clean = tree.record().expect("a clean record");
            let mut run = tree.run("", Some(clean));
            steps::run_all(&mut run, &REMOVE)
                .unwrap_or_else(|_| panic!("{stopped} {other}: removes"));
            assert!(
                std::fs::symlink_metadata(&file).is_ok(),
                "{stopped} {other}: left"
            );
            assert!(tree.record().is_none());
            assert_eq!(tree.leftovers(), Vec::<String>::new(), "{stopped} {other}");
            assert!(
                run.events
                    .iter()
                    .any(|event| matches!(event, Event::LeftFile)),
                "{stopped} {other}: the file is named as left"
            );
        }
    }
}

#[test]
fn a_leftover_is_removed_only_when_it_is_an_owner_only_regular_file_with_the_recorded_bytes() {
    for which in ["aside", "staging"] {
        for variant in [
            "other bytes",
            "wide mode",
            "directory",
            "link",
            "right bytes",
            "prefix",
        ] {
            let (tree, _) = Tree::published();
            let record = tree.record().expect("a record");
            let file = tree.file();
            let leftover = record::beside(
                &file,
                if which == "aside" {
                    "kr-moving"
                } else {
                    "kr-staging"
                },
            );
            let operation = if which == "aside" {
                Operation::Remove
            } else {
                Operation::Publish
            };
            let pending = Pending {
                operation,
                contents: None,
                aside: (which == "aside").then(|| leftover.clone()),
                staging: (which == "staging").then(|| leftover.clone()),
            };
            let pending_record = record.with(pending);
            write_owner_only_file_of_record(&tree, &pending_record);
            let want = |wanted: bool| (variant == "right bytes") == wanted;
            match variant {
                "other bytes" => write_owner_only(&leftover, b"nothing of ours\n", 0o600),
                "wide mode" => write_owner_only(&leftover, OLD.as_bytes(), 0o644),
                "directory" => std::fs::create_dir(&leftover).expect("a directory"),
                "link" => std::os::unix::fs::symlink(&file, &leftover).expect("a link"),
                "right bytes" => write_owner_only(&leftover, OLD.as_bytes(), 0o600),
                // A partly written staging file is the one state no stop between two steps makes:
                // a kill inside the write does, and this makes it by hand.
                _ => write_owner_only(&leftover, &OLD.as_bytes()[..3], 0o600),
            }
            let mut run = tree.run("", Some(pending_record.clone()));
            steps::settle(&mut run, &pending_record, Mode::Remove)
                .unwrap_or_else(|_| panic!("{which} {variant}: settles"));
            let gone = std::fs::symlink_metadata(&leftover).is_err();
            let removable = variant == "right bytes" || (which == "staging" && variant == "prefix");
            assert_eq!(
                gone, removable,
                "{which} {variant}: removed only when vouched"
            );
            let _ = want;
            assert_eq!(
                bytes(&file).as_deref(),
                Some(OLD.as_bytes()),
                "{which} {variant}"
            );
            assert!(
                run.events
                    .iter()
                    .any(|event| matches!(event, Event::Left(_)))
                    != removable,
                "{which} {variant}: a leftover that stays is named"
            );
        }
    }
}

fn write_owner_only_file_of_record(tree: &Tree, record: &Record) {
    kr_ipc::paths::write_owner_only_file(&record::path(&tree.state()), &record.bytes())
        .expect("writes the record");
}

#[test]
fn a_publication_that_failed_after_the_name_existed_is_finished_not_undone() {
    let tree = Tree::new();
    std::fs::create_dir_all(tree.directory()).expect("a directory");
    let guard = kr_flush::testing::refuse_flushes_of(tree.directory());
    let mut run = tree.run(NEW, None);
    let error = steps::run_all(&mut run, &PUBLISH).expect_err("the flush after the link fails");
    let failure = steps::fail(&mut run, Operation::Publish, error);
    assert!(matches!(failure.tail, Tail::InPlace));
    assert_eq!(
        bytes(&tree.file()).as_deref(),
        Some(NEW.as_bytes()),
        "not undone"
    );
    let record = tree.record().expect("a record");
    assert!(
        record.pending.is_some(),
        "the record keeps what is under way"
    );
    // A retry while the flushes still fail keeps the record as it is.
    let (mut again, pending) = tree.finishing();
    assert!(steps::settle(&mut again, &pending, Mode::Install).is_err());
    assert!(tree.record() == Some(record), "the record is retained");
    drop(guard);
    let (mut again, pending) = tree.finishing();
    assert!(steps::settle(&mut again, &pending, Mode::Install).is_ok_and(|s| s == Settled::Done));
    assert!(tree.record().expect("a record").pending.is_none());
    assert_eq!(tree.leftovers(), Vec::<String>::new());

    // The record's own last write can publish it and then fail to flush: the file is in place.
    let tree = Tree::new();
    std::fs::create_dir_all(tree.directory()).expect("a directory");
    let guard = kr_flush::testing::refuse_flushes_of(tree.state());
    let mut run = tree.run(NEW, None);
    let error = steps::run_all(&mut run, &PUBLISH[..1]).expect_err("the record flush fails");
    drop(guard);
    let failure = steps::fail(&mut run, Operation::Publish, error);
    assert!(
        matches!(failure.tail, Tail::TookBack),
        "nothing was written yet"
    );
    assert!(tree.record().is_none());
}

#[test]
fn a_flush_that_fails_keeps_the_record_naming_the_path_it_followed() {
    // The staging file is removed and its flush fails: the record still names it.
    let tree = Tree::new();
    std::fs::create_dir_all(tree.directory()).expect("a directory");
    let mut run = tree.run(NEW, None);
    steps::run_all(&mut run, &PUBLISH[..4]).unwrap_or_else(|_| panic!("runs"));
    let staging = run.paths.staging.clone();
    let guard = kr_flush::testing::refuse_flushes_of(tree.directory());
    assert!(
        steps::run_all(&mut run, &PUBLISH[4..]).is_err(),
        "the flush fails"
    );
    drop(guard);
    assert!(!staging.exists(), "the removal before the flush is done");
    assert_eq!(staging_of(&tree.record().expect("a record")), Some(staging));

    // The file is deleted at the removal's third step and its flush fails.
    let (tree, _) = Tree::published();
    let mut run = tree.run("", tree.record());
    steps::run_all(&mut run, &REMOVE[..2]).unwrap_or_else(|_| panic!("moved aside"));
    let aside = run.paths.aside.clone();
    let guard = kr_flush::testing::refuse_flushes_of(tree.directory());
    assert!(
        steps::run_all(&mut run, &REMOVE[2..]).is_err(),
        "the flush fails"
    );
    drop(guard);
    let record = tree.record().expect("the record stays");
    assert!(record.pending.is_some() && !aside.exists());

    // The aside is dropped after a put back and its flush fails.
    let tree = Tree::removing(2);
    let record = tree.record().expect("a record");
    let mut run = tree.run("", Some(record.clone()));
    run.paths.aside = aside_of(&record).expect("named");
    let guard = kr_flush::testing::refuse_flushes_of(tree.directory());
    assert!(
        steps::run_all(&mut run, &PUT_BACK).is_err(),
        "the flush fails"
    );
    drop(guard);
    assert!(tree.record().expect("the record stays").pending.is_some());
}

#[test]
fn a_removal_whose_aside_cannot_go_back_leaves_it_named_and_drops_the_record() {
    let (tree, _) = Tree::published();
    write_owner_only(&tree.file(), b"changed since\n", 0o600);
    let mut run = tree.run("", tree.record());
    steps::run_all(&mut run, &REMOVE[..2]).unwrap_or_else(|_| panic!("moved aside"));
    let aside = run.paths.aside.clone();
    write_owner_only(&tree.file(), b"another file\n", 0o600);
    steps::run_all(&mut run, &REMOVE[2..]).unwrap_or_else(|_| panic!("finishes"));
    assert_eq!(
        bytes(&aside).as_deref(),
        Some(&b"changed since\n"[..]),
        "the aside holds it"
    );
    assert_eq!(
        bytes(&tree.file()).as_deref(),
        Some(&b"another file\n"[..]),
        "the place is unchanged"
    );
    assert!(tree.record().is_none(), "the record is dropped");
    assert!(
        run.events
            .iter()
            .any(|e| matches!(e, Event::AsideStays(path) if *path == aside))
    );
}

fn parts<'a>(program: &'a str, runtime: &'a str, state: &'a str) -> Parts<'a> {
    Parts {
        label: LABEL,
        program,
        runtime_root: runtime,
        state_root: state,
        state_dir: "/s/environments/abcd1234",
        log: "/s/environments/abcd1234/controller.log",
    }
}

#[test]
fn the_property_list_and_the_desktop_entry_are_written_whole() {
    let given = parts("/k/kr-controller", "/r", "/s");
    let plist = render::render(Kind::LaunchAgent, &given).unwrap_or_else(|_| panic!("renders"));
    assert_eq!(
        plist,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <!-- The KalaReach control daemon, started when you log in. kr host login-item install wrote this file and kr host login-item remove takes it out. -->\n\
         <plist version=\"1.0\">\n<dict>\n\
         \t<key>Label</key>\n\t<string>kr-desktop-host-x</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n\
         \t\t<string>/k/kr-controller</string>\n\
         \t\t<string>--runtime-dir</string>\n\
         \t\t<string>/r</string>\n\
         \t\t<string>--state-dir</string>\n\
         \t\t<string>/s</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\t<true/>\n\
         \t<key>KeepAlive</key>\n\t<false/>\n\
         \t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n\
         \t<key>ProcessType</key>\n\t<string>Interactive</string>\n\
         \t<key>WorkingDirectory</key>\n\t<string>/s/environments/abcd1234</string>\n\
         \t<key>Umask</key>\n\t<integer>63</integer>\n\
         \t<key>StandardOutPath</key>\n\t<string>/s/environments/abcd1234/controller.log</string>\n\
         \t<key>StandardErrorPath</key>\n\t<string>/s/environments/abcd1234/controller.log</string>\n\
         </dict>\n</plist>\n"
    );
    let entry = render::render(Kind::AutostartEntry, &given).unwrap_or_else(|_| panic!("renders"));
    assert_eq!(
        entry,
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=KalaReach control daemon\n\
         Comment=Started when you log in. kr host login-item install wrote this file and kr host login-item remove takes it out.\n\
         Exec=\"/k/kr-controller\" \"--runtime-dir\" \"/r\" \"--state-dir\" \"/s\"\n\
         TryExec=/k/kr-controller\n\
         Path=/s/environments/abcd1234\n\
         Terminal=false\n"
    );
    assert!(!entry.contains("NoDisplay"));
}

#[test]
fn every_word_of_exec_is_quoted_and_these_characters_are_refused() {
    let line = |program: &str, runtime: &str, state: &str| {
        render::render(Kind::AutostartEntry, &parts(program, runtime, state))
            .ok()
            .map(|entry| {
                entry
                    .lines()
                    .find(|l| l.starts_with("Exec="))
                    .expect("an Exec line")
                    .to_owned()
            })
    };
    for name in [
        "a b", "a'b", "a#b", "a;b", "a(b", "a&b", "a<b", "a>b", "a~b", "a*b", "a?b", "a|b", "zoë",
    ] {
        let path = format!("/p/{name}");
        assert_eq!(
            line(&path, "/r", "/s"),
            Some(format!(
                "Exec=\"{path}\" \"--runtime-dir\" \"/r\" \"--state-dir\" \"/s\""
            )),
            "the daemon path {name}"
        );
        assert_eq!(
            line("/k", &path, "/s"),
            Some(format!(
                "Exec=\"/k\" \"--runtime-dir\" \"{path}\" \"--state-dir\" \"/s\""
            )),
            "the runtime root {name}"
        );
        assert_eq!(
            line("/k", "/r", &path),
            Some(format!(
                "Exec=\"/k\" \"--runtime-dir\" \"/r\" \"--state-dir\" \"{path}\""
            )),
            "the state root {name}"
        );
    }
    for bad in ["a\"b", "a`b", "a$b", "a\\b", "a%b"] {
        let path = format!("/p/{bad}");
        assert!(line(&path, "/r", "/s").is_none(), "the daemon path {bad}");
        assert!(line("/k", &path, "/s").is_none(), "the runtime root {bad}");
        assert!(line("/k", "/r", &path).is_none(), "the state root {bad}");
    }
    for unreadable in ["/p/a\tb", "/p/a\nb", " /p", "/p ", "p"] {
        assert!(
            render::text(Path::new(unreadable)).is_none(),
            "{unreadable:?}"
        );
    }
    assert!(
        line("/p/a=b", "/r", "/s").is_none(),
        "= in the daemon path is refused"
    );
    assert!(
        line("/k", "/p/a=b", "/s").is_some(),
        "= in the runtime root is accepted"
    );
    assert!(
        line("/k", "/r", "/p/a=b").is_some(),
        "= in the state root is accepted"
    );
}

#[test]
fn a_record_whose_paths_are_not_this_logins_own_is_refused_whole() {
    let tree = Tree::new();
    let (published, _) = Tree::published();
    let good = published.record().expect("a record");
    let file = published.file();
    let aside = record::beside(&file, "kr-moving");
    let staging = record::beside(&file, "kr-staging");
    let read = |value: &serde_json::Value| {
        write_owner_only(
            &record::path(&tree.state()),
            value.to_string().as_bytes(),
            0o600,
        );
        record::read(&tree.state(), tree.kind, LABEL, &Shown::said("the record")).err()
    };
    let json = |mutate: &dyn Fn(&mut serde_json::Value)| {
        let mut value = serde_json::to_value(&good).expect("a value");
        mutate(&mut value);
        value
    };
    assert!(read(&json(&|_| {})).is_none(), "the good record reads");
    let pending = |operation: &str, extra: serde_json::Value| {
        json(&|value| {
            let mut pending = serde_json::json!({ "operation": operation });
            for (key, item) in extra.as_object().expect("an object") {
                pending[key] = item.clone();
            }
            value["pending"] = pending;
        })
    };
    let bad = [
        json(&|v| v["version"] = 2.into()),
        json(&|v| v["unknown"] = 1.into()),
        json(&|v| {
            v["kind"] = if Kind::current() == Kind::LaunchAgent {
                "autostart_entry"
            } else {
                "launch_agent"
            }
            .into()
        }),
        json(&|v| v["label"] = "kr-controller-x".into()),
        json(&|v| v["path"] = "/etc/passwd".into()),
        json(&|v| {
            v["path"] = file
                .with_file_name("other.desktop")
                .to_string_lossy()
                .into_owned()
                .into()
        }),
        json(&|v| v["path"] = "relative".into()),
        pending(
            "remove",
            serde_json::json!({ "aside": "/elsewhere/.x.kr-moving" }),
        ),
        pending(
            "remove",
            serde_json::json!({ "aside": file.with_file_name(".other.kr-moving") }),
        ),
        pending("publish", serde_json::json!({ "staging": aside })),
        pending(
            "publish",
            serde_json::json!({ "staging": staging, "aside": aside }),
        ),
        pending("remove", serde_json::json!({ "staging": staging })),
        pending(
            "replace",
            serde_json::json!({ "staging": staging, "aside": aside }),
        ),
        pending(
            "publish",
            serde_json::json!({ "staging": staging, "other": 1 }),
        ),
    ];
    for (n, value) in bad.iter().enumerate() {
        assert!(read(value).is_some(), "case {n} is refused: {value}");
    }
    let fine = [
        pending("remove", serde_json::json!({ "aside": aside })),
        pending("publish", serde_json::json!({ "staging": staging })),
        pending(
            "replace",
            serde_json::json!({ "staging": staging, "aside": aside, "contents": "x" }),
        ),
    ];
    for (n, value) in fine.iter().enumerate() {
        assert!(
            read(value).is_none(),
            "shape {n} is this login's own: {value}"
        );
    }
    std::fs::write(record::path(&tree.state()), b"not json").expect("a file");
    assert!(record::read(&tree.state(), tree.kind, LABEL, &Shown::said("r")).is_err());
}
