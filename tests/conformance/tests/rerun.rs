//! A step whose first run ends in a file the linker wrote that the system would not start is run
//! again, and the result says so; any other failure is left as it is.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use kr_conformance::fault::Cause;
use kr_conformance::fault::{self, Budget, Reads};
#[cfg(unix)]
use kr_conformance::plan::Platform;
use kr_conformance::plan::{Group, Reading, Step};
#[cfg(unix)]
use kr_conformance::report::{self, Document, Options};
use kr_conformance::run::Place;

/// A step that, on its first run, writes a program under the target directory, empty or a copy of
/// the file its third argument names, and ends as a build does when the system refuses to start a
/// build script, and succeeds on its second.
const SCRIPT: &str = "marker=$1; file=$2; source=$3; \
    if [ ! -e \"$marker\" ]; then \
      : > \"$marker\"; mkdir -p \"$(dirname \"$file\")\"; \
      if [ -n \"$source\" ]; then cp \"$source\" \"$file\"; else : > \"$file\"; fi; chmod +x \"$file\"; \
      echo \"process didn't exit successfully: \\`$file\\` (exit status: 126)\"; \
      echo \"$file: $file: cannot execute binary file\"; \
      exit 101; \
    fi; \
    echo second-$((1 + 1)); exit 0";

/// The step, given the marker that says it ran once, the program it writes and, where the program
/// is not to be empty, the file it is a copy of.
fn step(arguments: &[&Path]) -> Step {
    let mut command: Vec<String> = ["sh", "-c", SCRIPT, "sh"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    command.extend(
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned()),
    );
    Step {
        group: Group::Rust,
        what: "a build that links a program".to_owned(),
        command,
        needs: Vec::new(),
        reading: Reading::Build,
        filter: None,
        skips: Vec::new(),
    }
}

/// A line of the kernel's log that says a write to storage failed.
#[cfg(unix)]
const KERNEL_FAULT: &str =
    "2026-11-14 01:02:03 E  kernel[0]: (IOStorageFamily) disk2s5: I/O error.\n";

/// The free space, in KiB, of a volume with room: 40 GiB.
#[cfg(unix)]
const ROOM: u64 = 40 * 1024 * 1024;

/// The free space, in KiB, of a volume that was full: 500 MiB.
#[cfg(unix)]
const ROOM_UNDER_FLOOR: u64 = 500 * 1024;

/// What the system's evidence says in a case: the kernel's log (the lines it holds, or why it could
/// not be read) and the lowest free space of the volume, in KiB (or why it could not be read).
#[cfg(unix)]
#[derive(Clone, Copy)]
struct Evidence {
    kernel: Result<&'static str, &'static str>,
    free: Result<u64, &'static str>,
}

#[cfg(unix)]
impl Evidence {
    /// The kernel logged a storage error, and the volume had room.
    const SHOWN: Self = Self {
        kernel: Ok(KERNEL_FAULT),
        free: Ok(ROOM),
    };

    fn reads(self) -> Reads {
        Reads {
            kernel_log: Box::new(move |_, _, out| match self.kernel {
                Ok(text) => std::fs::write(out, text).map_err(|error| error.to_string()),
                Err(why) => Err(why.to_owned()),
            }),
            free_space: Box::new(move |_, _, _| self.free.map_err(str::to_owned)),
        }
    }
}

/// Evidence that a case that is not run again must never ask for.
fn no_evidence() -> Reads {
    Reads {
        kernel_log: Box::new(|_, _, _| {
            panic!("the kernel's log is read only for a step run again")
        }),
        free_space: Box::new(|_, _, _| panic!("the volume is read only for a step run again")),
    }
}

/// A repository, an evidence directory and a target directory with a profile directory in it.
#[cfg(unix)]
struct Tree {
    directory: tempfile::TempDir,
    root: PathBuf,
    evidence: PathBuf,
    profile: PathBuf,
    marker: PathBuf,
    environment: [(String, String); 1],
}

#[cfg(unix)]
impl Tree {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("repository");
        let evidence = directory.path().join("evidence");
        let profile = root.join("target/debug");
        std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
        std::fs::create_dir_all(&evidence).unwrap();
        let marker = directory.path().join("ran-once");
        let environment = [(
            "CARGO_TARGET_DIR".to_owned(),
            root.join("target").to_string_lossy().into_owned(),
        )];
        Self {
            directory,
            root,
            evidence,
            profile,
            marker,
            environment,
        }
    }

    fn place(&self) -> Place<'_> {
        Place {
            root: &self.root,
            evidence: &self.evidence,
            environment: &self.environment,
            lister: Path::new("/nonexistent/kr-conformance"),
        }
    }
}

#[cfg(unix)]
#[test]
fn a_step_that_linked_an_empty_program_is_run_again_and_the_result_names_the_runner_s_disk() {
    let tree = Tree::new();
    let unit = "x-0123456789abcdef";
    std::fs::create_dir_all(tree.profile.join(".fingerprint").join(unit)).unwrap();
    let program = tree
        .profile
        .join("build")
        .join(unit)
        .join("build-script-build");
    let mut told = Vec::new();
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        7,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &Evidence::SHOWN.reads(),
        &mut |line| told.push(line.to_owned()),
    );
    assert_eq!(done.exit, Some(0), "the second run passed");
    assert_eq!(done.error, None);
    let rerun = done.rerun.expect("the step was run again");
    assert_eq!(rerun.cause, Cause::RunnerDisk);
    assert_eq!(rerun.first_exit, Some(101));
    assert_eq!(
        rerun.files,
        ["target/debug/build/x-0123456789abcdef/build-script-build"]
    );
    assert!(
        rerun.reason.contains("the file is empty"),
        "{}",
        rerun.reason
    );
    assert!(rerun.removed >= 2, "the directory and the unit's records");
    assert!(!program.exists(), "the damaged program is removed");
    assert!(!tree.profile.join(".fingerprint").join(unit).exists());
    let first = std::fs::read_to_string(tree.evidence.join(&rerun.first_log)).unwrap();
    assert!(first.contains("cannot execute binary file"));
    assert!(!first.contains("second-2"));
    let second = std::fs::read_to_string(tree.evidence.join(&done.log)).unwrap();
    assert!(second.contains("second-2"));
    assert_ne!(rerun.first_log, done.log);
    let facts = std::fs::read_to_string(tree.evidence.join(&rerun.facts)).unwrap();
    assert!(
        facts.contains("Mach-O header: the file is empty"),
        "{facts}"
    );
    assert!(told.iter().any(|line| line.contains("is run again")));
}

#[test]
fn a_step_that_fails_in_another_way_is_not_run_again() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("repository");
    let evidence = directory.path().join("evidence");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evidence).unwrap();
    let mut failing = step(&[]);
    failing.command = ["sh", "-c", "echo $0 >> ran; exit 3", "once"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    let place = Place {
        root: &root,
        evidence: &evidence,
        environment: &[],
        lister: Path::new("/nonexistent/kr-conformance"),
    };
    let done = fault::execute(
        &failing,
        1,
        &place,
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &no_evidence(),
        &mut |_| {},
    );
    assert_eq!(done.exit, Some(3));
    assert!(done.rerun.is_none());
    assert_eq!(
        std::fs::read_to_string(root.join("ran"))
            .unwrap()
            .lines()
            .count(),
        1,
        "the step ran once"
    );
}

/// A file under the target directory that is not a program Cargo built, such as a program a test
/// of the repository leaves there or one that is in a profile directory with no record of it in
/// Cargo's, is not a reason to run a step again, whatever the log says of it.
#[cfg(unix)]
#[test]
fn a_file_that_no_build_wrote_is_not_a_reason_to_run_a_step_again() {
    for program in ["target/fixtures/helper", "target/debug/helper"] {
        let tree = Tree::new();
        let program = tree.root.join(program);
        let done = fault::execute(
            &step(&[&tree.marker, &program]),
            1,
            &tree.place(),
            &[],
            &mut Budget::of(Duration::from_secs(3600)),
            &no_evidence(),
            &mut |_| {},
        );
        assert_eq!(done.exit, Some(101), "the step ran once");
        assert!(done.rerun.is_none(), "{}", program.display());
        assert!(program.exists(), "the file is left where it is");
    }
}

/// Two runs of a step that took longer than the time the report leaves for second runs would end
/// the report before it wrote its result, so the step is not run again, and says why.
#[cfg(unix)]
#[test]
fn a_step_whose_first_run_took_longer_than_the_time_left_is_not_run_again() {
    let tree = Tree::new();
    std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
    let program = tree
        .profile
        .join("build/x-0123456789abcdef/build-script-build");
    let mut slow = step(&[&tree.marker, &program]);
    slow.command[2] = format!("sleep 1; {SCRIPT}");
    let mut nothing_left = Budget::of(Duration::ZERO);
    let done = fault::execute(
        &slow,
        1,
        &tree.place(),
        &[],
        &mut nothing_left,
        &no_evidence(),
        &mut |_| {},
    );
    assert_eq!(done.exit, Some(101), "the step ran once");
    assert!(done.rerun.is_none());
    let error = done.error.expect("the step has the reason");
    assert!(error.contains("is not run again"), "{error}");
}

/// What a second run takes is taken from the time left for second runs, so that a step after it
/// finds less, and none, there.
#[cfg(unix)]
#[test]
fn the_time_a_second_run_takes_is_taken_from_the_time_left_for_second_runs() {
    let mut left = Budget::of(Duration::from_secs(1));
    let run = |left: &mut Budget| {
        let tree = Tree::new();
        std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
        let program = tree
            .profile
            .join("build/x-0123456789abcdef/build-script-build");
        let mut slow = step(&[&tree.marker, &program]);
        slow.command[2] = format!("sleep 1; {SCRIPT}");
        fault::execute(
            &slow,
            1,
            &tree.place(),
            &[],
            left,
            &Evidence::SHOWN.reads(),
            &mut |_| {},
        )
    };
    let first = run(&mut left);
    assert!(first.rerun.is_some(), "the first step was run again");
    assert_eq!(
        left.left(),
        Duration::ZERO,
        "its second run took the second left"
    );
    let second = run(&mut left);
    assert!(
        second.rerun.is_none(),
        "nothing was left for the second step"
    );
    assert_eq!(second.exit, Some(101));
    let error = second.error.expect("the step has the reason");
    assert!(error.contains("is not run again"), "{error}");
}

/// The step's script, with what its second run does in place of passing: it names its own number
/// and its child's in the file its fourth argument names, and waits for the child, which sleeps far
/// longer than any case lets a second run take.
#[cfg(unix)]
fn script_with_a_sleeping_second_run() -> String {
    let passing = "echo second-$((1 + 1)); exit 0";
    assert!(SCRIPT.contains(passing));
    SCRIPT.replacen(
        passing,
        "echo $$ > \"$4\"; sleep 120 & echo $! >> \"$4\"; wait",
        1,
    )
}

/// Whether the process with this number is running. A process that ended and has not been
/// collected yet is not.
#[cfg(unix)]
fn running(pid: u32) -> bool {
    let output = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let state = String::from_utf8_lossy(&output.stdout);
    !state.trim().is_empty() && !state.trim().starts_with('Z')
}

/// Ends, by their exact numbers, the processes a case started that are still running: where the
/// case's own assertions failed, they are not left to sleep.
#[cfg(unix)]
struct Started(Vec<u32>);

#[cfg(unix)]
impl Drop for Started {
    fn drop(&mut self) {
        for pid in self.0.iter().filter(|pid| running(**pid)) {
            let _ = std::process::Command::new("kill")
                .args(["-s", "KILL", &pid.to_string()])
                .status();
        }
    }
}

/// A step that sleeps in its second run, run under `budget`: the step's error is the second run's
/// deadline, the step's processes are gone, and the report keeps what the step did.
#[cfg(unix)]
fn run_a_step_that_sleeps_in_its_second_run(
    mut budget: Budget,
) -> (kr_conformance::run::Executed, Started) {
    let tree = Tree::new();
    let (program, _unit) = unit_of(&tree);
    let pids = tree.directory.path().join("pids");
    let mut sleeping = step(&[&tree.marker, &program, Path::new(""), &pids]);
    sleeping.command[2] = script_with_a_sleeping_second_run();
    let done = fault::execute(
        &sleeping,
        1,
        &tree.place(),
        &[],
        &mut budget,
        &Evidence::SHOWN.reads(),
        &mut |_| {},
    );
    let numbers: Vec<u32> = std::fs::read_to_string(&pids)
        .expect("the second run named its processes")
        .lines()
        .map(|line| line.trim().parse().expect("a process number"))
        .collect();
    assert_eq!(numbers.len(), 2, "the shell and its child: {numbers:?}");
    (done, Started(numbers))
}

/// That none of the processes is running, allowing a moment for the system to collect the ones that
/// were not the run's own children.
#[cfg(unix)]
fn assert_gone(started: &Started) {
    for _ in 0..100 {
        if !started.0.iter().any(|pid| running(*pid)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "a process of the second run is still running: {:?}",
        started.0
    );
}

/// A second run whose program ends by itself, having started a process it did not wait for, leaves
/// that process in the step's group: it is ended with the run, and the step's own exit is kept.
#[cfg(unix)]
#[test]
fn a_second_run_that_ends_by_itself_leaves_no_process_of_its_group_behind() {
    let tree = Tree::new();
    let (program, _unit) = unit_of(&tree);
    let pids = tree.directory.path().join("pids");
    let mut leaving = step(&[&tree.marker, &program, Path::new(""), &pids]);
    leaving.command[2] = SCRIPT.replacen(
        "echo second-$((1 + 1)); exit 0",
        "echo $$ > \"$4\"; sleep 120 & echo $! >> \"$4\"; exit 0",
        1,
    );
    let done = fault::execute(
        &leaving,
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &Evidence::SHOWN.reads(),
        &mut |_| {},
    );
    let started = Started(
        std::fs::read_to_string(&pids)
            .unwrap()
            .lines()
            .map(|line| line.trim().parse().unwrap())
            .collect(),
    );
    assert_eq!(done.exit, Some(0), "the second run ended by itself");
    assert_eq!(done.error, None);
    assert_gone(&started);
}

/// What the second run of a step that sleeps came to, and that none of its processes is left. The
/// step ends red, not green, with the reason, and the evidence of the first run is still in its
/// result.
#[cfg(unix)]
fn assert_ended_at_its_deadline(done: &kr_conformance::run::Executed, started: &Started) {
    assert_eq!(done.exit, None, "the second run did not end by itself");
    let error = done.error.as_deref().expect("the step has an error");
    assert!(error.contains(fault::PASSED_ITS_TIME), "{error}");
    let rerun = done.rerun.as_ref().expect("the step was run again");
    assert_eq!(rerun.first_exit, Some(101));
    assert_gone(started);
}

/// A second run that is still going when the time left for second runs is up is ended: the group
/// of its processes is asked to end and then killed, the step ends red, and no process of it stays.
#[cfg(unix)]
#[test]
fn a_second_run_that_passes_the_time_left_is_ended_with_its_processes_and_the_step_ends_red() {
    let (done, started) =
        run_a_step_that_sleeps_in_its_second_run(Budget::of(Duration::from_secs(2)));
    assert_ended_at_its_deadline(&done, &started);
}

/// The job's limit ends a second run as well, less the time the report keeps to write its result,
/// whichever is sooner: here the account would allow an hour, and the limit leaves two seconds.
#[cfg(unix)]
#[test]
fn a_second_run_is_ended_at_the_jobs_limit_less_the_reserve_where_that_is_sooner() {
    let ends = std::time::SystemTime::now() + fault::RESULT_RESERVE + Duration::from_secs(2);
    let budget = Budget::of(Duration::from_secs(3600)).until(ends);
    let (done, started) = run_a_step_that_sleeps_in_its_second_run(budget);
    assert_ended_at_its_deadline(&done, &started);
}

/// Where the job's limit is nearer than the time the report keeps for its result, the step is not
/// run again at all.
#[cfg(unix)]
#[test]
fn a_step_is_not_run_again_where_the_jobs_limit_leaves_less_than_the_reserve() {
    let tree = Tree::new();
    let (program, _unit) = unit_of(&tree);
    let ends = std::time::SystemTime::now() + Duration::from_secs(30);
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)).until(ends),
        &no_evidence(),
        &mut |_| {},
    );
    assert_run_once_with_reason(&done, "left for a second run");
}

/// A step run again whose first run's evidence could not be kept ends red, whatever its second run
/// came to.
#[cfg(unix)]
#[test]
fn a_step_run_again_whose_first_runs_evidence_was_not_kept_ends_red() {
    let tree = Tree::new();
    std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
    // The directory for the facts cannot be made where a file stands.
    std::fs::create_dir_all(tree.evidence.join("conformance")).unwrap();
    std::fs::write(tree.evidence.join("conformance/faults"), "").unwrap();
    let program = tree
        .profile
        .join("build/x-0123456789abcdef/build-script-build");
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &Evidence::SHOWN.reads(),
        &mut |_| {},
    );
    assert_eq!(done.exit, Some(0), "the second run passed");
    assert!(done.rerun.is_some());
    let error = done.error.expect("the step has an error");
    assert!(error.contains("evidence was not kept"), "{error}");
}

/// A unit's build script of the tree, written by the step's first run, and the unit's directory and
/// its records, which exist before the step runs.
#[cfg(unix)]
fn unit_of(tree: &Tree) -> (PathBuf, PathBuf) {
    let unit = tree.profile.join("build/x-0123456789abcdef");
    std::fs::create_dir_all(&unit).unwrap();
    std::fs::create_dir_all(tree.profile.join(".fingerprint/x-0123456789abcdef")).unwrap();
    (unit.join("build-script-build"), unit)
}

/// What a step that was refused its second run says, and that it ran once.
#[cfg(unix)]
fn assert_run_once_with_reason(done: &kr_conformance::run::Executed, reason: &str) {
    assert_eq!(done.exit, Some(101), "the step ran once");
    assert!(done.rerun.is_none(), "the step was run again");
    let error = done.error.as_deref().expect("the step has the reason");
    assert!(error.contains("is not run again"), "{error}");
    assert!(error.contains(reason), "{error}");
}

/// A link below a unit is not followed, and the removal takes nothing of the unit: a removal that
/// took the unit and left the link would be a removal of something else on another night.
#[cfg(unix)]
#[test]
fn a_link_below_a_unit_ends_the_step_red_with_nothing_of_the_unit_removed_and_no_second_run() {
    let tree = Tree::new();
    let (program, unit) = unit_of(&tree);
    let outside = tree.directory.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("kept"), "kept").unwrap();
    std::os::unix::fs::symlink(&outside, unit.join("out")).unwrap();
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &no_evidence(),
        &mut |_| {},
    );
    assert_run_once_with_reason(&done, "is a link");
    assert!(program.exists(), "the program is left where it is");
    assert!(unit.join("out").symlink_metadata().is_ok());
    assert!(outside.join("kept").exists());
}

/// A file of the unit that was there before the step began is not one the step's build wrote: it
/// is not removed, and the step is not run again.
#[cfg(unix)]
#[test]
fn a_file_of_a_unit_that_the_step_did_not_write_is_not_removed_and_the_step_is_not_run_again() {
    let tree = Tree::new();
    let (program, _unit) = unit_of(&tree);
    let old = tree
        .profile
        .join(".fingerprint/x-0123456789abcdef/invoked.timestamp");
    std::fs::write(&old, "").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(24 * 60 * 60))
        .unwrap();
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &no_evidence(),
        &mut |_| {},
    );
    assert_run_once_with_reason(&done, "was not written since the step began");
    assert!(old.exists(), "the old file is left where it is");
    assert!(program.exists());
}

/// What lies under a unit changes after the first plan, while the evidence is read (the kernel's
/// log can take a minute and a half): a link is put in where a directory was. The plan that is
/// carried out is the one made right before, so it sees the link; the removal takes nothing of the
/// unit and the step is not run again.
#[cfg(unix)]
#[test]
fn a_link_put_in_a_unit_while_the_evidence_is_read_stops_the_removal_and_the_second_run() {
    let tree = Tree::new();
    let (program, unit) = unit_of(&tree);
    let outside = tree.directory.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("kept"), "kept").unwrap();
    std::fs::create_dir_all(unit.join("out")).unwrap();
    let out = unit.join("out");
    let reads = Reads {
        kernel_log: Box::new(move |_, _, file| {
            // Between the plan and the removal, the directory becomes a link to another place.
            std::fs::remove_dir(&out).map_err(|error| error.to_string())?;
            std::os::unix::fs::symlink(&outside, &out).map_err(|error| error.to_string())?;
            std::fs::write(file, KERNEL_FAULT).map_err(|error| error.to_string())
        }),
        free_space: Box::new(|_, _, _| Ok(ROOM)),
    };
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &reads,
        &mut |_| {},
    );
    assert_run_once_with_reason(&done, "is a link");
    assert!(program.exists(), "the program is left where it is");
    assert!(tree.directory.path().join("outside/kept").exists());
}

/// A disk image of 4 MiB, in the case's own directory on the disk the temporary directory is on,
/// attached with no browser window at a directory of the case's own, never under `/Volumes`. It
/// is detached when this is dropped, which happens on every ending of the case that unwinds. The
/// image's file name is the case's name, so that a run that was killed and left its image
/// attached can be found with `hdiutil info | grep a_mount_below_a_unit` and ended with
/// `hdiutil detach -force <the mount point it shows>`.
#[cfg(target_os = "macos")]
struct Mounted(PathBuf);

#[cfg(target_os = "macos")]
impl Mounted {
    /// Makes the image from the files of `source`, so that nothing but `hdiutil` writes to it, and
    /// attaches it at `directory`. Where the image cannot be made or attached, the case fails with
    /// what `hdiutil` said.
    fn at(directory: &Path, image: &Path, source: &Path) -> Self {
        let run = |command: &mut std::process::Command| {
            let output = command
                .stdin(std::process::Stdio::null())
                .output()
                .expect("hdiutil could not be started");
            assert!(
                output.status.success(),
                "hdiutil {:?} failed: {}{}",
                command.get_args().collect::<Vec<_>>(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(std::process::Command::new("hdiutil")
            .args(["create", "-size", "4m", "-fs", "HFS+", "-ov", "-srcfolder"])
            .arg(source)
            .arg(image));
        run(std::process::Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-noverify", "-mountpoint"])
            .arg(directory)
            .arg(image));
        Self(directory.to_path_buf())
    }
}

#[cfg(target_os = "macos")]
impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", "-force"])
            .arg(&self.0)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// A directory below a unit that is a mount of another volume is not entered: a removal that
/// entered it would empty it. The step is not run again, and what is on the mounted volume stays.
/// The image's one file is written by `hdiutil` when the image is made; the case reads nothing
/// from the image but whether that file is still there.
#[cfg(target_os = "macos")]
#[test]
fn a_mount_below_a_unit_is_not_entered_and_the_step_is_not_run_again() {
    let tree = Tree::new();
    let (program, unit) = unit_of(&tree);
    let point = unit.join("out");
    std::fs::create_dir_all(&point).unwrap();
    let source = tree.directory.path().join("volume-source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("kept"), "kept").unwrap();
    let image = tree
        .directory
        .path()
        .join("a_mount_below_a_unit_is_not_entered_and_the_step_is_not_run_again.dmg");
    let _mounted = Mounted::at(&point, &image, &source);
    let done = fault::execute(
        &step(&[&tree.marker, &program]),
        1,
        &tree.place(),
        &[],
        &mut Budget::of(Duration::from_secs(3600)),
        &no_evidence(),
        &mut |_| {},
    );
    assert_run_once_with_reason(&done, "is on another device");
    assert!(point.join("kept").exists(), "what the mount holds stays");
    assert!(program.exists());
}

/// The report over the `forms` tree with `step` as its only step, building into `target`, with the
/// cause of a rerun read from `evidence`.
#[cfg(unix)]
fn report_over(
    steps: Vec<Step>,
    target: &Path,
    evidence: &Path,
    reads: &Reads,
    budget: Budget,
) -> Document {
    let options = Options {
        root: Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("forms"),
        evidence: kr_conformance::evidence::check_directory(evidence)
            .expect("inside the temporary directory"),
        selection: Some(vec![Group::Rust]),
        all_terminals: false,
        platform: Platform::current(),
        case_tables: &[],
        lanes: &[],
        ignored_runs: None,
        applications: None,
        steps: Some(steps),
        lister: PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance")),
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )],
        part: None,
    };
    report::run_with(&options, reads, budget, &mut |_| {})
        .unwrap_or_else(|stopped| panic!("{stopped:?}"))
}

/// A report over a step that writes `source` (or an empty file) where a build script goes, in a
/// target directory with a profile directory.
#[cfg(unix)]
fn rerun_report(
    source: Option<&Path>,
    evidence: Evidence,
) -> (Document, tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let kept = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = directory.path().join("target");
    std::fs::create_dir_all(target.join("debug/.fingerprint/x-0123456789abcdef")).unwrap();
    let program = target
        .join("debug/build/x-0123456789abcdef")
        .join("build-script-build");
    let marker = directory.path().join("ran-once");
    let mut arguments: Vec<&Path> = vec![&marker, &program];
    arguments.extend(source);
    let document = report_over(
        vec![step(&arguments)],
        &target,
        kept.path(),
        &evidence.reads(),
        Budget::of(Duration::from_secs(3600)),
    );
    (document, kept, program)
}

/// A run in which a step linked a program that was empty, the kernel logged a storage error and
/// the volume had room, and the second run passed: the run passes, with one warning annotation
/// naming the step and the program, and the count as its last line.
#[cfg(unix)]
#[test]
fn a_run_with_a_step_run_again_passes_where_the_runner_s_disk_is_shown_and_says_so() {
    let (document, _evidence, program) = rerun_report(None, Evidence::SHOWN);
    assert!(document.passed(), "{:?}", document.summary.failed_steps);
    assert_eq!(document.summary.rerun_steps, [1]);
    let annotations = document.rerun_annotations();
    assert_eq!(annotations.len(), 1, "{annotations:?}");
    let expected = format!(
        "::warning title=Step 1 was run again::step 1, a build that links a program, was run \
         again after a file that could not be started: {}; the runner's disk: ",
        program.display()
    );
    assert!(annotations[0].starts_with(&expected), "{annotations:?}");
    assert!(!annotations[0].contains('\n'));
    assert_eq!(
        document.rerun_count_line().as_deref(),
        Some("1 steps were run again after a file that could not be started")
    );
}

/// A program of ours that is damaged is as empty as one the runner's disk damaged, and the same
/// goes for a whole program the system refused: only the kernel's own line, with a volume that
/// had room, shows the runner's disk. Without it the second run passes and the run still ends
/// red, with no warning, and says what is missing.
#[cfg(unix)]
#[test]
fn a_run_with_a_step_run_again_ends_red_with_no_warning_where_the_evidence_is_not_all_there() {
    let source = tempfile::tempdir().unwrap();
    let script = source.path().join("script");
    std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    let full = ROOM_UNDER_FLOOR;
    let cases: [(&str, Option<&Path>, Evidence, &str); 5] = [
        (
            "a damaged program and no line of the kernel's log",
            None,
            Evidence {
                kernel: Ok(""),
                free: Ok(ROOM),
            },
            "the kernel logged no storage error",
        ),
        (
            "a damaged program and a kernel line, on a volume that was full",
            None,
            Evidence {
                kernel: Ok(KERNEL_FAULT),
                free: Ok(full),
            },
            "the volume was full",
        ),
        (
            "a damaged program and a kernel log that could not be read",
            None,
            Evidence {
                kernel: Err("no sudo"),
                free: Ok(ROOM),
            },
            "the kernel's log was not read: no sudo",
        ),
        (
            "a whole program and no line of the kernel's log",
            Some(script.as_path()),
            Evidence {
                kernel: Ok(""),
                free: Ok(ROOM),
            },
            "no damage found",
        ),
        (
            "a damaged program, a kernel line and a volume whose free space could not be read",
            None,
            Evidence {
                kernel: Ok(KERNEL_FAULT),
                free: Err("no df"),
            },
            "the volume's free space was not read: no df",
        ),
    ];
    for (what, source, evidence, said) in cases {
        let (document, _kept, _) = rerun_report(source, evidence);
        let rerun = document.steps[0].rerun.as_ref().expect("run again");
        assert_eq!(rerun.cause, Cause::Unexplained, "{what}: {}", rerun.reason);
        assert!(rerun.reason.contains(said), "{what}: {}", rerun.reason);
        assert_eq!(
            document.steps[0].exit,
            Some(0),
            "{what}: the second run passed"
        );
        assert!(!document.passed(), "{what}");
        assert_eq!(document.summary.failed_steps, [1], "{what}");
        assert!(document.rerun_annotations().is_empty(), "{what}");
        assert_eq!(document.rerun_count_line(), None, "{what}");
    }
}

/// A program the linker signed, copied whole, is accepted by the system's check of signatures, so
/// where nothing else shows the runner's disk the run ends red. This is the case that a refusal
/// that the system's check makes of every program would turn into a pass.
#[cfg(target_os = "macos")]
#[test]
fn a_whole_program_the_linker_signed_is_not_taken_for_the_runner_s_disk() {
    let program = std::env::current_exe().unwrap();
    let nothing_logged = Evidence {
        kernel: Ok(""),
        free: Ok(ROOM),
    };
    let (document, _evidence, _) = rerun_report(Some(&program), nothing_logged);
    let rerun = document.steps[0].rerun.as_ref().expect("run again");
    assert_eq!(rerun.cause, Cause::Unexplained, "{}", rerun.reason);
    assert!(
        rerun.reason.contains("signature is valid"),
        "{}",
        rerun.reason
    );
    assert!(!document.passed());
    assert!(document.rerun_annotations().is_empty());
}

/// A second run that is ended at its deadline does not stop the report: the step is red with the
/// reason, the step after it runs, and the run returns its result, which is not a pass.
#[cfg(unix)]
#[test]
fn the_report_returns_its_result_after_a_second_run_that_passed_its_time() {
    let directory = tempfile::tempdir().unwrap();
    let kept = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let target = directory.path().join("target");
    let unit = target.join("debug/build/x-0123456789abcdef");
    std::fs::create_dir_all(&unit).unwrap();
    std::fs::create_dir_all(target.join("debug/.fingerprint/x-0123456789abcdef")).unwrap();
    let marker = directory.path().join("ran-once");
    let pids = directory.path().join("pids");
    let program = unit.join("build-script-build");
    let mut sleeping = step(&[&marker, &program, Path::new(""), &pids]);
    sleeping.command[2] = script_with_a_sleeping_second_run();
    let mut after = step(&[]);
    after.what = "a step after it".to_owned();
    after.command = ["sh", "-c", "exit 0", "after"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    let document = report_over(
        vec![sleeping, after],
        &target,
        kept.path(),
        &Evidence::SHOWN.reads(),
        Budget::of(Duration::from_secs(2)),
    );
    let numbers: Vec<u32> = std::fs::read_to_string(&pids)
        .unwrap()
        .lines()
        .map(|line| line.trim().parse().unwrap())
        .collect();
    let started = Started(numbers);
    let error = document.steps[0]
        .error
        .as_deref()
        .expect("the step's error");
    assert!(error.contains(fault::PASSED_ITS_TIME), "{error}");
    assert_eq!(document.steps[1].exit, Some(0), "the step after it ran");
    assert!(!document.passed());
    assert_eq!(document.summary.failed_steps, [1]);
    assert!(document.rerun_annotations().is_empty());
    for _ in 0..100 {
        if !started.0.iter().any(|pid| running(*pid)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "a process of the second run is still running: {:?}",
        started.0
    );
}

/// A run in which no step was run again prints neither the warning nor the count.
#[cfg(unix)]
#[test]
fn a_run_with_no_step_run_again_prints_no_warning_and_no_count() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let mut passing = step(&[]);
    passing.command = ["sh", "-c", "exit 0", "once"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
    let document = report_over(
        vec![passing],
        &directory.path().join("target"),
        evidence.path(),
        &no_evidence(),
        Budget::of(Duration::from_secs(3600)),
    );
    assert!(document.passed());
    assert!(document.summary.rerun_steps.is_empty());
    assert!(document.rerun_annotations().is_empty());
    assert_eq!(document.rerun_count_line(), None);
}
