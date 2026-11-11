//! What a group of processes holds, each resident page once (`kr_perf::memory`).
//!
//! The reader is checked in three ways. Most checks read a stand-in `/proc` tree of files this test
//! writes, in the form the kernel's are (a `maps` listing, a page map of one 64-bit entry for each
//! page of address space, a start time and a resident size), so that every case the definition names
//! is built exactly and the figure is known to the page. Some start copies of this test's own
//! program and read them from a child reader as the idle measurement does, because what the kernel
//! shows of a process that has ended, or that refuses to be read, or that read memory it never
//! wrote, is the kernel's. The rest start python3 processes that map files at chosen offsets and
//! write chosen pages, and read them from the live kernel in this process, because a Rust test
//! cannot map a file without `unsafe` code.

#![cfg(unix)]

use std::os::unix::fs::FileExt as _;
use std::path::Path;

use kr_perf::memory::{
    Class, Failure, Proc, Reading, agreement, classes_from_spec, classes_to_spec, with_retries,
};

/// The page size the stand-in trees are written for.
const PAGE: u64 = 4096;

/// What a page of a stand-in page map is.
#[derive(Clone, Copy)]
enum Page {
    /// A page of a file, or of shared memory: the kernel sets bit 61.
    File,
    /// A page that is the process's own: anonymous, or a private file page that was written.
    Own,
    /// A page that is swapped out: bit 62, and not present.
    Swapped,
}

/// One process of a stand-in tree.
struct Stand {
    pid: u32,
    start: String,
    maps: Vec<String>,
    entries: Vec<(u64, u64)>,
    end_page: u64,
    rss_kib: Option<u64>,
    /// How many bytes the page map is cut short by.
    short_by: u64,
    /// Whether the page map is left out.
    no_page_map: bool,
}

impl Stand {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            start: "1000".to_owned(),
            maps: Vec::new(),
            entries: Vec::new(),
            end_page: 0,
            rss_kib: None,
            short_by: 0,
            no_page_map: false,
        }
    }

    /// A mapping of `pages` pages from page `first` of the address space, of `path` (empty for none)
    /// from page `from` of the file `inode` on the device `device`.
    fn map(&mut self, first: u64, pages: u64, from: u64, device: &str, inode: u64, path: &str) {
        self.maps.push(format!(
            "{:x}-{:x} r--p {:08x} {device} {inode} {path}",
            first * PAGE,
            (first + pages) * PAGE,
            from * PAGE
        ));
        self.end_page = self.end_page.max(first + pages);
    }

    /// `count` resident pages of `kind` from page `first` of the address space.
    fn resident(&mut self, first: u64, count: u64, kind: Page) {
        let entry = match kind {
            Page::File => (1 << 63) | (1 << 61),
            Page::Own => 1 << 63,
            Page::Swapped => 1 << 62,
        };
        for page in first..first + count {
            self.entries.push((page, entry));
        }
    }

    fn write(&self, root: &Path) {
        let dir = root.join(self.pid.to_string());
        std::fs::create_dir_all(&dir).expect("a stand-in process directory");
        // The command name holds a space and a parenthesis, as a real one can; the start time is the
        // twentieth field after the last parenthesis.
        let mut fields = vec!["0".to_owned(); 22];
        fields[0] = "S".to_owned();
        fields[19].clone_from(&self.start);
        std::fs::write(
            dir.join("stat"),
            format!("{} (a (name) with space) {}\n", self.pid, fields.join(" ")),
        )
        .expect("stat");
        std::fs::write(dir.join("maps"), self.maps.join("\n") + "\n").expect("maps");
        let present = self
            .entries
            .iter()
            .filter(|(_, entry)| entry & (1 << 63) != 0)
            .count() as u64;
        std::fs::write(
            dir.join("smaps_rollup"),
            format!(
                "00400000-ffffffffff601000 ---p 00000000 00:00 0 [rollup]\nRss:  {} kB\nPss:  1 kB\n",
                self.rss_kib.unwrap_or(present * PAGE / 1024)
            ),
        )
        .expect("smaps_rollup");
        if !self.no_page_map {
            let pagemap = std::fs::File::create(dir.join("pagemap")).expect("pagemap");
            pagemap
                .set_len((self.end_page * 8).saturating_sub(self.short_by))
                .expect("its length");
            for (page, entry) in &self.entries {
                let offset = page * 8;
                if offset + 8 <= self.end_page * 8 - self.short_by {
                    pagemap
                        .write_all_at(&entry.to_ne_bytes(), offset)
                        .expect("an entry");
                }
            }
        }
    }
}

/// A stand-in `/proc` of the processes given.
fn tree(processes: &[Stand]) -> (tempfile::TempDir, Proc) {
    let dir = tempfile::tempdir().expect("a directory of its own");
    for process in processes {
        process.write(dir.path());
    }
    let proc = Proc::at(dir.path(), PAGE);
    (dir, proc)
}

fn group(pids: &[u32]) -> Vec<Class> {
    vec![Class {
        name: "group".to_owned(),
        pids: pids.to_vec(),
    }]
}

/// KR-PERF-003: a page every process of the group maps is counted once for the group, and a page of
/// a process's own for each process, so that the memory the group holds is not counted by what each
/// process maps.
#[test]
fn a_page_of_a_file_that_every_process_maps_is_counted_once_for_the_group() {
    let mut processes = Vec::new();
    for pid in [10, 11, 12] {
        let mut stand = Stand::new(pid);
        // Four pages of one program, resident in all three, and two pages of the process's own.
        stand.map(16, 8, 0, "08:01", 77, "/usr/lib/libshared.so");
        stand.resident(16, 4, Page::File);
        stand.map(64, 4, 0, "00:00", 0, "");
        stand.resident(64, 2, Page::Own);
        processes.push(stand);
    }
    let (_dir, proc) = tree(&processes);

    let reading = proc.read(&group(&[10, 11, 12])).expect("a reading");

    assert_eq!(reading.files_kib, 4 * 4, "the four file pages once");
    assert_eq!(reading.own_kib, 3 * 2 * 4, "two own pages for each process");
    assert_eq!(reading.combined_kib, 16 + 24);
    assert_eq!(
        reading.resident_kib,
        3 * 6 * 4,
        "the sum of resident sizes counts the file pages for each process"
    );
    let file = reading
        .file("/usr/lib/libshared.so")
        .expect("the file is named");
    assert_eq!(
        (file.once_kib, file.each_kib),
        (16, 48),
        "once for the group and for each process"
    );
}

/// A file page is the same page wherever a process maps it: it is identified by its device, its
/// inode and its place in the file, so overlapping and disjoint ranges of one file make a union.
#[test]
fn file_pages_are_identified_by_their_place_in_the_file_and_not_by_their_address() {
    // One file of 12 pages. The first process maps it whole at page 16 and has pages 0 to 3 resident
    // (file pages 0 to 3). The second maps it from file page 2, at another address, and has its
    // first four pages resident (file pages 2 to 5). The third maps pages 8 to 11 and has all of
    // them resident. Another file with the same inode number on another device is not the same file.
    let mut first = Stand::new(20);
    first.map(16, 12, 0, "08:01", 5, "/data/a");
    first.resident(16, 4, Page::File);
    let mut second = Stand::new(21);
    second.map(1000, 10, 2, "08:01", 5, "/data/a");
    second.resident(1000, 4, Page::File);
    let mut third = Stand::new(22);
    third.map(40, 4, 8, "08:01", 5, "/data/a");
    third.resident(40, 4, Page::File);
    third.map(80, 2, 0, "08:02", 5, "/other/a");
    third.resident(80, 2, Page::File);
    let (_dir, proc) = tree(&[first, second, third]);

    let reading = proc.read(&group(&[20, 21, 22])).expect("a reading");

    // File pages 0 to 5 and 8 to 11 of the first file, and two of the other.
    assert_eq!(reading.files_kib, (6 + 4 + 2) * 4);
    assert_eq!(reading.file("/data/a").map(|file| file.once_kib), Some(40));
    assert_eq!(reading.file("/other/a").map(|file| file.once_kib), Some(8));
    assert_eq!(reading.own_kib, 0);
}

/// Only a page the kernel marks as a file page, of a mapping that has an inode, is shared. A
/// private file page that was written, and shared memory with no inode, belong to each process.
#[test]
fn a_written_page_of_a_private_file_mapping_and_a_shared_page_with_no_inode_count_for_each_process()
{
    let mut processes = Vec::new();
    for pid in [30, 31] {
        let mut stand = Stand::new(pid);
        // Four pages of a file, of which the process has written two: they are its own.
        stand.map(16, 4, 0, "08:01", 9, "/data/b");
        stand.resident(16, 2, Page::File);
        stand.resident(18, 2, Page::Own);
        // Shared memory with no inode: its pages are file-or-shared by the kernel's bit and are
        // counted for each process that maps them.
        stand.map(64, 3, 0, "00:01", 0, "");
        stand.resident(64, 3, Page::File);
        processes.push(stand);
    }
    let (_dir, proc) = tree(&processes);

    let reading = proc.read(&group(&[30, 31])).expect("a reading");

    assert_eq!(reading.files_kib, 2 * 4, "the two unwritten pages, once");
    assert_eq!(
        reading.own_kib,
        2 * (2 + 3) * 4,
        "the two written pages and the three shared ones, for each process"
    );
}

/// KR-PERF-003: a page in swap is not resident, so it is not among the pages in memory; it is counted
/// apart for each process whose page map shows it, and the figure the bound is held to includes it,
/// so that a reading taken on a host that swaps does not read lower than the same group's resident
/// size on a host that does not.
#[test]
fn a_page_in_swap_is_counted_apart_for_each_process_that_shows_it_and_the_held_figure_includes_it()
{
    let mut first = Stand::new(40);
    first.map(16, 8, 0, "00:00", 0, "");
    first.resident(16, 3, Page::Own);
    first.resident(19, 3, Page::Swapped);
    let mut second = Stand::new(41);
    second.map(16, 8, 0, "00:00", 0, "");
    second.resident(16, 1, Page::Own);
    second.resident(17, 2, Page::Swapped);
    let (_dir, proc) = tree(&[first, second]);

    let reading = proc.read(&group(&[40, 41])).expect("a reading");

    assert_eq!(
        reading.resident_kib,
        4 * 4,
        "only the pages in memory are resident"
    );
    assert_eq!(reading.combined_kib, 4 * 4);
    assert_eq!(
        reading.swapped_kib,
        5 * 4,
        "each process counts the pages its map shows"
    );
    assert_eq!(
        reading.held_kib(),
        9 * 4,
        "the held figure is memory and swap"
    );
    let class = reading.class("group").expect("the class");
    assert_eq!(
        class.swapped_kib,
        5 * 4,
        "the class shows its own pages in swap"
    );

    let mut lines = reading.to_lines();
    lines.push("memory.end".to_owned());
    assert_eq!(
        Reading::from_lines(lines.iter().map(String::as_str)),
        Ok(reading),
        "and the pages in swap are what the caller reads back"
    );
}

/// The mapping the kernel never lets a program read lies beyond the page map of any process, and
/// holds nothing in a resident size.
#[test]
fn the_vsyscall_mapping_is_not_read() {
    let mut stand = Stand::new(50);
    stand.map(16, 2, 0, "00:00", 0, "");
    stand.resident(16, 2, Page::Own);
    stand
        .maps
        .push("ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]".to_owned());
    let (_dir, proc) = tree(&[stand]);

    let reading = proc
        .read(&group(&[50]))
        .expect("the mapping is passed over");

    assert_eq!(reading.combined_kib, 2 * 4);
}

/// KR-PERF-003: a scan that finds fewer pages than the kernel's own resident size has lost some and
/// is refused, by more than the larger of 64 KiB and one per cent. One that finds more is accepted,
/// with the excess recorded.
#[test]
fn a_scan_that_finds_fewer_pages_than_the_kernel_is_refused_and_one_that_finds_more_is_accepted() {
    let scan = |kernel_kib: u64| {
        let mut stand = Stand::new(60);
        stand.map(16, 1024, 0, "00:00", 0, "");
        stand.resident(16, 1024, Page::Own); // 4,096 KiB found
        stand.rss_kib = Some(kernel_kib);
        let (_dir, proc) = tree(&[stand]);
        proc.read(&group(&[60]))
    };

    // The kernel says 4,096 + 100 KiB: more than 64 KiB, and 41 KiB is one per cent.
    let refused = scan(4096 + 100).expect_err("a scan that lost pages");
    assert!(
        refused.contains("process 60") && refused.contains("4196"),
        "the refusal names the process and the kernel's figure: {refused}"
    );
    // Within the tolerance, short.
    let inside = scan(4096 + 60).expect("60 KiB short is inside 64 KiB");
    assert_eq!(
        inside.shortfall_kib, 60,
        "and what the scan may have missed is recorded"
    );
    assert_eq!(
        inside.held_kib(),
        4096 + 60,
        "and the figure the bound is held to includes it"
    );
    // The kernel's figure is under the scan's: the zero pages a resident size leaves out.
    let more = scan(4096 - 8).expect("a scan above the kernel's size is accepted");
    assert_eq!(more.beyond_kib, 8, "the excess is recorded");
    assert_eq!(more.shortfall_kib, 0, "and nothing was missed");
    assert_eq!(
        more.combined_kib, 4096,
        "and the pages it found are counted"
    );
    // The same rule, as the function that decides it: one per cent of a large process.
    assert!(agreement(1, 99_000, 100_000).is_ok());
    assert!(agreement(1, 98_900, 100_000).is_err());
}

/// A reading that cannot be taken whole is refused, naming the process, and is never a smaller
/// figure.
#[test]
fn a_process_whose_page_map_cannot_be_read_whole_is_refused_with_its_pid() {
    let build = |short_by: u64, no_page_map: bool| {
        let mut stand = Stand::new(70);
        stand.map(16, 8, 0, "00:00", 0, "");
        stand.resident(16, 8, Page::Own);
        stand.short_by = short_by;
        stand.no_page_map = no_page_map;
        let mut healthy = Stand::new(71);
        healthy.map(16, 8, 0, "00:00", 0, "");
        healthy.resident(16, 8, Page::Own);
        let (dir, proc) = tree(&[stand, healthy]);
        let result = proc.read(&group(&[71, 70]));
        drop(dir);
        result
    };

    let missing = build(0, true).expect_err("no page map");
    assert!(missing.contains("process 70"), "{missing}");
    let short = build(16, false).expect_err("a page map that ends too soon");
    assert!(
        short.contains("process 70") && short.contains("short"),
        "{short}"
    );
    assert!(build(0, false).is_ok(), "the same tree whole is read");
}

/// Each class is read apart, and a file page two classes map counts once in each.
#[test]
fn each_class_is_read_apart_and_a_file_page_two_classes_map_counts_once_in_each() {
    let mut processes = Vec::new();
    for (pid, own) in [(80, 1), (81, 2), (90, 4)] {
        let mut stand = Stand::new(pid);
        stand.map(16, 8, 0, "08:01", 3, "/usr/lib/libc.so");
        stand.resident(16, 8, Page::File);
        stand.map(64, 8, 0, "00:00", 0, "");
        stand.resident(64, own, Page::Own);
        processes.push(stand);
    }
    let (_dir, proc) = tree(&processes);
    let classes = vec![
        Class {
            name: "workers".to_owned(),
            pids: vec![80, 81],
        },
        Class {
            name: "daemon".to_owned(),
            pids: vec![90],
        },
    ];

    let reading = proc.read(&classes).expect("a reading");

    let workers = reading.class("workers").expect("the workers");
    assert_eq!(
        (workers.processes, workers.own_kib, workers.files_kib),
        (2, 3 * 4, 8 * 4)
    );
    let daemon = reading.class("daemon").expect("the daemon");
    assert_eq!(
        (daemon.processes, daemon.own_kib, daemon.files_kib),
        (1, 4 * 4, 8 * 4)
    );
    assert_eq!(
        reading.files_kib,
        8 * 4,
        "the whole group counts the file's pages once"
    );
    assert_eq!(reading.combined_kib, (1 + 2 + 4) * 4 + 8 * 4);
}

/// A process is scanned again only while its mappings change, up to three times; any other failure
/// ends the reading at once.
#[test]
fn a_process_is_scanned_again_only_while_its_mappings_change() {
    let changed = || Failure::Changed("its mappings changed".to_owned());

    let mut calls = 0;
    let settled = with_retries(|| {
        calls += 1;
        if calls == 1 {
            Err(changed())
        } else {
            Ok(calls)
        }
    });
    assert_eq!(settled, Ok(2), "one change, then a scan that settles");

    let mut calls = 0;
    let never = with_retries::<()>(|| {
        calls += 1;
        Err(changed())
    });
    assert_eq!(calls, 3, "three scans in all");
    assert!(
        never.is_err_and(|reason| reason.contains("mappings changed")),
        "and then a refusal that says why"
    );

    let mut calls = 0;
    let other = with_retries::<()>(|| {
        calls += 1;
        Err(Failure::Refused("process 1: it cannot be read".to_owned()))
    });
    assert_eq!(calls, 1, "any other failure is final");
    assert_eq!(other, Err("process 1: it cannot be read".to_owned()));
}

/// What the reader prints is what its caller reads, and a refusal it prints is the caller's.
#[test]
fn what_the_reader_prints_is_read_back_and_a_refusal_it_prints_is_the_callers() {
    let mut stand = Stand::new(100);
    stand.map(16, 4, 0, "08:01", 2, "/opt/kr worker/kr-worker");
    stand.resident(16, 4, Page::File);
    stand.map(64, 2, 0, "00:00", 0, "");
    stand.resident(64, 2, Page::Own);
    let (_dir, proc) = tree(&[stand]);
    let reading = proc.read(&group(&[100])).expect("a reading");

    let mut lines = reading.to_lines();
    lines.push("memory.end".to_owned());
    let read = Reading::from_lines(lines.iter().map(String::as_str)).expect("read back");
    assert_eq!(read, reading, "a path with a space comes back whole");

    let cut = Reading::from_lines(lines.iter().map(String::as_str).take(2));
    assert!(
        cut.is_err(),
        "a result that stops before its end is no result"
    );
    let refused = Reading::from_lines(["memory.refused process 7: reading its maps: gone"]);
    assert_eq!(refused, Err("process 7: reading its maps: gone".to_owned()));

    let classes = vec![
        Class {
            name: "workers".to_owned(),
            pids: vec![1, 2],
        },
        Class {
            name: "daemon".to_owned(),
            pids: vec![3],
        },
    ];
    let spec = classes_to_spec(&classes);
    assert_eq!(
        classes_from_spec(&spec),
        Ok(classes),
        "the classes the child is told are the classes it reads"
    );
}

/// An object the kernel makes for a process (an `anon_inode:` file) has an inode number that does
/// not name a file whose pages other processes share, so its pages are counted for each process.
#[test]
fn the_pages_of_a_kernel_object_are_counted_for_each_process() {
    let mut processes = Vec::new();
    for pid in [110, 111] {
        let mut stand = Stand::new(pid);
        stand.map(16, 4, 0, "00:0f", 12345, "anon_inode:[object]");
        stand.resident(16, 4, Page::File);
        processes.push(stand);
    }
    let (_dir, proc) = tree(&processes);

    let reading = proc.read(&group(&[110, 111])).expect("a reading");

    assert_eq!(reading.files_kib, 0, "none of them is counted once");
    assert_eq!(reading.own_kib, 2 * 4 * 4, "each process counts its own");
}

#[cfg(target_os = "linux")]
mod linux {
    use kr_perf::memory::{
        Hold, Holder, Watched, hold_if_asked, program_of, read_in_child, serve_if_asked,
    };

    use super::{Class, group};

    /// What a holder writes, in mebibytes.
    const HELD_MIB: usize = 8;

    /// How many holders the group has.
    const HOLDERS: usize = 4;

    fn holders_class(pids: &[u32]) -> Vec<Class> {
        group(pids)
    }

    /// Four copies of this program, each holding eight mebibytes of its own, are read from a child
    /// reader: the program they all map is counted once for the group, what each wrote is counted
    /// for each, and the pages found agree with `ps`.
    #[test]
    fn processes_that_run_one_program_are_read_by_a_child_with_the_program_counted_once() {
        if serve_if_asked() || hold_if_asked() {
            return;
        }
        const THIS: &str = "linux::processes_that_run_one_program_are_read_by_a_child_with_the_program_counted_once";
        let holders: Vec<Holder> = (0..HOLDERS)
            .map(|_| Holder::spawn(THIS, HELD_MIB, Hold::Written).expect("a holder starts"))
            .collect();
        let pids: Vec<u32> = holders.iter().map(Holder::pid).collect();

        let reading = read_in_child(THIS, &holders_class(&pids)).expect("the group is read");

        assert_eq!(reading.processes, HOLDERS);
        assert!(
            reading.own_kib >= (HOLDERS * HELD_MIB * 1024) as u64,
            "what each holder wrote is counted for each of them: {} KiB",
            reading.own_kib
        );
        assert!(reading.combined_kib < reading.resident_kib);
        let program = program_of(pids[0]).expect("the holder's program");
        let file = reading.file(&program).expect("the program is named");
        assert!(
            file.once_kib * 3 <= file.each_kib,
            "four copies map the program, which is counted once, not four times: {} KiB once, \
             {} KiB for each process",
            file.once_kib,
            file.each_kib
        );
        let table = kr_perf::process::resident_kib(&pids).expect("ps reads the holders");
        let sum: u64 = table.values().sum();
        assert!(
            reading.resident_kib.abs_diff(sum) <= sum / 100 + 64 * HOLDERS as u64,
            "the scan found {} KiB and the process table sums to {sum} KiB",
            reading.resident_kib
        );
    }

    /// A process that has ended and not been reaped has no page map to read, and a process that
    /// refuses its page map to every reader gives it to none: each is refused with its identifier,
    /// not read as a smaller figure.
    #[test]
    fn a_process_that_has_ended_or_will_not_be_read_is_refused_with_its_pid() {
        if serve_if_asked() || hold_if_asked() {
            return;
        }
        const THIS: &str =
            "linux::a_process_that_has_ended_or_will_not_be_read_is_refused_with_its_pid";

        let mut ended = Holder::spawn(THIS, 1, Hold::Written).expect("a holder starts");
        let pid = ended.end_unreaped().expect("it ends");
        // `end_unreaped` returns once the process has exited and not been reaped: a zombie.
        let refused = read_in_child(THIS, &holders_class(&[pid])).expect_err("a zombie");
        assert!(refused.contains(&format!("process {pid}")), "{refused}");
        drop(ended);

        // Root reads every page map, so the refusal of a process that will not be read is the
        // kernel's for any other user.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let hidden = Holder::spawn(THIS, 1, Hold::Undumpable).expect("an undumpable holder starts");
        let refused = read_in_child(THIS, &holders_class(&[hidden.pid()]))
            .expect_err("a process that cannot be read");
        assert!(
            refused.contains(&format!("process {}", hidden.pid()))
                && refused.contains("Permission denied"),
            "{refused}"
        );
    }

    /// The reader waits for the process it starts by a bound and ends one that stays: a child that
    /// is still running when the bound passes is not reported as exited, is killed by its process
    /// descriptor and is then reported as exited, and a child that has exited is a zombie until it is
    /// reaped, and says how it ended.
    #[test]
    fn a_watched_child_is_waited_for_by_a_bound_and_killed_by_its_descriptor() {
        let mut staying =
            Watched::spawn(std::process::Command::new("sleep").arg("600")).expect("sleep starts");
        assert!(
            !staying.exited_within(std::time::Duration::from_millis(50)),
            "a child that is still running has not exited when the bound passes"
        );
        assert!(
            staying.kill_and_wait_for_exit(),
            "a killed child exits inside the grace"
        );
        assert!(
            staying.reap().contains("signal: 9"),
            "and was ended by the kill"
        );

        let mut leaving =
            Watched::spawn(&mut std::process::Command::new("true")).expect("true starts");
        assert!(
            leaving.exited_within(std::time::Duration::from_secs(30)),
            "a child that leaves is seen to"
        );
        assert!(
            std::fs::read_to_string(format!("/proc/{}/stat", leaving.id()))
                .is_ok_and(|stat| stat.contains(") Z ")),
            "and is a zombie, not yet reaped"
        );
        assert!(leaving.reap().contains("exit status: 0"), "until it is");
    }

    /// Memory a process has read and never written is the kernel's shared zero page, which the page
    /// map shows as present and the kernel's own resident size leaves out. The reading is accepted
    /// and the excess is recorded, in the conservative direction.
    #[test]
    fn memory_that_was_read_and_never_written_is_accepted_with_the_excess_recorded() {
        if serve_if_asked() || hold_if_asked() {
            return;
        }
        const THIS: &str =
            "linux::memory_that_was_read_and_never_written_is_accepted_with_the_excess_recorded";
        const READ_MIB: usize = 32;
        let holder = Holder::spawn(THIS, READ_MIB, Hold::Read).expect("a holder starts");

        let reading = read_in_child(THIS, &holders_class(&[holder.pid()]))
            .expect("a scan that finds more than the kernel's size is accepted");

        assert!(
            reading.beyond_kib >= (READ_MIB * 1024 / 2) as u64,
            "most of the {READ_MIB} MiB it read is found beyond the kernel's resident size: {} KiB",
            reading.beyond_kib
        );
        assert!(
            reading.own_kib >= (READ_MIB * 1024 / 2) as u64,
            "and counted: {} KiB",
            reading.own_kib
        );
    }
}

/// What the kernel shows of pages that are mapped by file and by offset, written through a mapping.
/// A Rust test cannot map a file without `unsafe`, so each process here is a python3 that maps a file
/// and writes the pages it is asked to (the same kind of helper the repository's other mapping
/// checks use), and the reader reads it from the live kernel.
#[cfg(target_os = "linux")]
mod mappings {
    use std::io::{BufRead as _, Write as _};

    use kr_perf::memory::{Class, Proc, Watched};

    /// The program every mapping process runs: maps `length` pages of a file (or of a memory file it
    /// makes) from page `offset`, shared or private, reads the first byte of every page of it when
    /// asked to, says `ready` and the descriptor it mapped, and waits for a line; then writes the
    /// first byte of `count` pages from page `first` of the mapping, says `held`, and waits for its
    /// input to close. A write to a page of a shared file
    /// mapping maps that page and no other; a write to a page of a private file mapping gives the
    /// process a copy of it.
    const MAPPER: &str = r#"import mmap, os, sys
kind, path, offset, length, first, count, preread = sys.argv[1:8]
page = mmap.PAGESIZE
offset, length, first, count = (int(value) for value in (offset, length, first, count))
offset *= page
length *= page
if kind == "memfd":
    fd = os.memfd_create("kr-perf-check")
    os.ftruncate(fd, length)
    flags = mmap.MAP_SHARED
else:
    fd = os.open(path, os.O_RDWR)
    flags = mmap.MAP_PRIVATE if kind == "private" else mmap.MAP_SHARED
view = mmap.mmap(fd, length, flags=flags, prot=mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
if preread == "1":
    for index in range(length // page):
        view[index * page]
print("ready", fd, flush=True)
sys.stdin.readline()
for index in range(first, first + count):
    view[index * page] = 1
print("held", fd, flush=True)
sys.stdin.readline()
"#;

    /// A process that holds a mapping, for as long as this value lives.
    struct Mapper {
        child: Watched,
        input: Option<std::process::ChildStdin>,
        said: std::sync::mpsc::Receiver<String>,
        fd: i64,
    }

    impl Mapper {
        /// Starts a mapping process and waits until it has mapped its pages, and read all of them if
        /// `preread` says so; it writes none yet.
        fn spawn(
            kind: &str,
            path: &str,
            [offset, length, first, count]: [u64; 4],
            preread: bool,
        ) -> Self {
            let mut child = Watched::spawn(
                std::process::Command::new("python3")
                    .args(["-I", "-c", MAPPER, kind, path])
                    .args([offset, length, first, count].map(|number| number.to_string()))
                    .arg(if preread { "1" } else { "0" })
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::inherit()),
            )
            .expect("python3 starts, to map the pages the case reads");
            let output = child.child().stdout.take().expect("its output");
            let input = child.child().stdin.take();
            let (sending, said) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(output)
                    .lines()
                    .map_while(Result::ok)
                {
                    let _ = sending.send(line);
                }
            });
            let mut mapper = Self {
                child,
                input,
                said,
                fd: -1,
            };
            mapper.fd = mapper
                .wait_for("ready ")
                .parse()
                .expect("the descriptor it mapped");
            mapper
        }

        /// What a line that starts with `prefix` says after it, within a minute.
        fn wait_for(&self, prefix: &str) -> String {
            let line = self
                .said
                .recv_timeout(std::time::Duration::from_secs(60))
                .unwrap_or_else(|_| panic!("the mapping process says `{}`", prefix.trim()));
            line.strip_prefix(prefix)
                .unwrap_or_else(|| panic!("`{line}` is not `{}`", prefix.trim()))
                .trim()
                .to_owned()
        }

        /// Has the process write its pages, and waits until it has.
        fn write_pages(&mut self) {
            let input = self.input.as_mut().expect("its input");
            writeln!(input).expect("the process is asked to write");
            input.flush().expect("and told");
            self.wait_for("held ");
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    /// The page size of this host, in kibibytes.
    fn page_kib() -> u64 {
        rustix::param::page_size() as u64 / 1024
    }

    /// A file of `pages` pages in a directory on the disk this build runs on, and the path the kernel
    /// names its mappings by. Not in `/tmp`, which can be memory: a memory file system can map a huge
    /// page for one fault.
    fn file_of_pages(pages: usize) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("a directory");
        let file = dir.path().join("pages");
        std::fs::write(&file, vec![7_u8; pages * rustix::param::page_size()]).expect("the file");
        let path = std::fs::canonicalize(&file).expect("its path");
        (dir, path.to_string_lossy().into_owned())
    }

    fn read(pids: &[u32]) -> kr_perf::memory::Reading {
        Proc::system()
            .read(&[Class {
                name: "group".to_owned(),
                pids: pids.to_vec(),
            }])
            .expect("the processes are read")
    }

    /// KR-PERF-003: two processes map one file at different offsets and write overlapping ranges of
    /// its pages: the file's pages are counted as the union of the ranges once for the group, and for
    /// each process they are counted by what that process maps. A third process outside the group
    /// that writes the same pages and others leaves the group's figure as it was.
    #[test]
    fn a_file_mapped_at_two_offsets_is_counted_as_the_union_of_the_pages_written() {
        let (_dir, path) = file_of_pages(16);
        // File pages 0 to 3, and 2 to 5 (from offset 2, the first four pages of its mapping). A third
        // process outside the group writes pages 0 to 9: the pages the group's two share, and more.
        let mut first = Mapper::spawn("shared", &path, [0, 8, 0, 4], false);
        let mut second = Mapper::spawn("shared", &path, [2, 8, 0, 4], false);
        let mut outside = Mapper::spawn("shared", &path, [0, 12, 0, 10], false);
        first.write_pages();
        second.write_pages();
        outside.write_pages();

        let reading = read(&[first.pid(), second.pid()]);

        let file = reading.file(&path).expect("the file is named");
        assert_eq!(file.once_kib, 6 * page_kib(), "pages 0 to 5, once");
        assert_eq!(
            file.each_kib,
            8 * page_kib(),
            "four pages for each of the two processes"
        );
    }

    /// KR-PERF-003: a write to a private file mapping gives the process its own copy of the page, so
    /// pages it had read as pages of the file become its own and leave the file's count, where the
    /// same writes through a shared mapping make pages of the file. The private process reads every
    /// page before the write, so that the pages move; each process is read before and after its
    /// write, so that what differs is what the write did.
    #[test]
    fn a_write_to_a_private_file_mapping_moves_its_pages_from_the_file_to_the_process() {
        const PAGES: u64 = 64;
        let (_dir, path) = file_of_pages(PAGES as usize);
        let mut shared = Mapper::spawn("shared", &path, [0, PAGES, 0, PAGES], false);
        let mut private = Mapper::spawn("private", &path, [0, PAGES, 0, PAGES], true);
        let before_shared = read(&[shared.pid()]);
        let before_private = read(&[private.pid()]);
        shared.write_pages();
        private.write_pages();
        let after_shared = read(&[shared.pid()]);
        let after_private = read(&[private.pid()]);

        assert!(
            before_shared.file(&path).is_none(),
            "a mapping nothing has touched holds no page of the file"
        );
        assert_eq!(
            before_private.file(&path).map(|file| file.once_kib),
            Some(PAGES * page_kib()),
            "the pages the private process read are pages of the file"
        );
        assert_eq!(
            after_shared.file(&path).map(|file| file.once_kib),
            Some(PAGES * page_kib()),
            "the pages written through the shared mapping are pages of the file"
        );
        assert!(
            after_private.file(&path).is_none(),
            "the pages the private process wrote have left the file's count: {:?}",
            after_private.file(&path)
        );
        assert!(
            after_private.own_kib >= before_private.own_kib + PAGES * page_kib() * 9 / 10,
            "and are its own: {} KiB after, {} KiB before",
            after_private.own_kib,
            before_private.own_kib
        );
    }

    /// KR-PERF-003: shared memory that has an inode is counted once for the group, however many
    /// processes map it: one process makes a memory file and writes pages 0 to 3, another opens it
    /// through the first one's descriptor and writes pages 2 to 5.
    #[test]
    fn shared_memory_that_has_an_inode_is_counted_once() {
        let mut maker = Mapper::spawn("memfd", "-", [0, 8, 0, 4], false);
        let opened = format!("/proc/{}/fd/{}", maker.pid(), maker.fd);
        let mut other = Mapper::spawn("shared", &opened, [0, 8, 2, 4], false);
        maker.write_pages();
        other.write_pages();

        let reading = read(&[maker.pid(), other.pid()]);

        let memory = reading
            .files
            .iter()
            .find(|file| file.path.starts_with("/memfd:kr-perf-check"))
            .expect("the memory file is named");
        assert_eq!(memory.once_kib, 6 * page_kib(), "pages 0 to 5, once");
        assert_eq!(memory.each_kib, 8 * page_kib());
    }
}
