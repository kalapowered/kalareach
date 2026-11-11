//! The memory a group of processes holds, each resident page counted once for the group (Linux).
//!
//! Section 27 bounds the memory the controller and twenty idle sessions hold. A resident size
//! counts a page of a file that twenty workers map twenty times, once for each of them, so the sum
//! of resident sizes is far above what the group holds. This reads the kernel's page map for every
//! process of the group and counts, page by page:
//!
//! * a resident page the kernel marks as a file page or as shared memory (bit 61 of the page map's
//!   entry) of a mapping that has an inode is identified by its device, inode and page of the file,
//!   and counted once for the whole group, whether or not a process outside the group maps it too;
//!   the one exception is the kernel's own objects (an `anon_inode:` file), whose inode number does
//!   not name a file whose pages are shared;
//! * every other resident page (anonymous memory, a page of a private file mapping that has been
//!   written, a shared page with no inode) is counted once for each process that maps it. Pages that
//!   processes share through a fork, or that the kernel has merged, are counted for each of them, so
//!   the figure can only be above the physical set there.
//!
//! A page the page map shows as present counts, including the shared zero page that a read of
//! untouched memory maps. The kernel's resident size leaves those out, so a scan can find more than
//! the kernel's size, and the excess is kept in [`Reading::beyond_kib`]. A scan that finds fewer
//! pages than the kernel's resident size by more than the larger of 64 KiB and one per cent has lost
//! some and is refused, so an accepted reading can fall short of the pages a process holds by up to
//! that much. A page in swap (bit 62 of its entry) is not resident, but it is counted apart for the
//! process whose page map shows it, and the figure the bound is held to includes it
//! ([`Reading::held_kib`]): a reading taken while the host swaps must not read lower than the same
//! group's resident size on a host that does not.
//!
//! A reading that cannot be taken whole is a refusal that names the process and what failed, never a
//! smaller figure. A process is scanned at most [`ATTEMPTS`] times in all, and again only when its
//! mappings changed while it was scanned.
//!
//! The reader runs in a child copy of the test's own program (`read_in_child`), because the
//! controller is the process being read: a reader inside it would allocate its own page set in the
//! process it is counting. The child needs the processes of the group to stay dumpable by their own
//! user, since the kernel shows a page map only to a process that may trace the one it describes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::path::PathBuf;

/// The page map's bit for a page that is in memory.
const PRESENT: u64 = 1 << 63;

/// The page map's bit for a page of a file or of shared memory.
const FILE_OR_SHARED: u64 = 1 << 61;

/// The page map's bit for a page that is in swap; it means something only where [`PRESENT`] is
/// clear.
const SWAPPED: u64 = 1 << 62;

/// How many page map entries one read takes.
const CHUNK_PAGES: u64 = 1 << 16;

/// How many times a process is scanned while its mappings keep changing.
pub const ATTEMPTS: u32 = 3;

/// The one mapping the kernel never lets a program read: it lies above a process's address space
/// and its page is not part of the process's resident size.
const UNREADABLE_BY_DESIGN: &str = "[vsyscall]";

/// The least a scan may fall short of the kernel's resident size before it is refused.
const LEAST_TOLERANCE_KIB: u64 = 64;

/// The environment variable that makes a copy of the test's program the reader, holding the
/// processes it reads.
pub const ROLE: &str = "KR_PERF_MEMORY_READER";

/// How long a copy of the test's program has: the reader from its start to its exit, and a holder
/// from its start to saying it holds its memory. One still running then is stopped.
#[cfg(target_os = "linux")]
const READER_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// A named set of processes whose reading is kept apart, such as the session workers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    /// What the class is called in a record: lower-case words and underscores.
    pub name: String,
    /// The processes of the class.
    pub pids: Vec<u32>,
}

/// What a class held, in kibibytes, each file page once within the class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassReading {
    /// The class's name.
    pub name: String,
    /// How many processes it has.
    pub processes: usize,
    /// Every resident page, counted for each process that maps it.
    pub resident_kib: u64,
    /// The pages counted for each process.
    pub own_kib: u64,
    /// The file pages, each once for the class.
    pub files_kib: u64,
    /// `own_kib` and `files_kib` together: the pages in memory.
    pub combined_kib: u64,
    /// The pages in swap, counted for each process whose page map shows them.
    pub swapped_kib: u64,
}

/// What a file holds in the group, in kibibytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReading {
    /// The path the kernel names the mapping by.
    pub path: String,
    /// Its resident pages, each once for the group.
    pub once_kib: u64,
    /// Its resident pages, counted for each process that maps them, as a sum of resident sizes does.
    pub each_kib: u64,
}

/// What the group holds, in kibibytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reading {
    /// How many processes were read.
    pub processes: usize,
    /// Every resident page the scan found, counted for each process that maps it.
    pub resident_kib: u64,
    /// The pages counted for each process.
    pub own_kib: u64,
    /// The file pages, each once for the group.
    pub files_kib: u64,
    /// `own_kib` and `files_kib` together: the memory the group holds in memory.
    pub combined_kib: u64,
    /// The pages in swap, counted for each process whose page map shows them. They are not
    /// resident, and a host that does not swap would have them resident.
    pub swapped_kib: u64,
    /// How far the scan's pages are above the kernel's own resident sizes, in all: the zero pages
    /// and huge pages it leaves out of a resident size.
    pub beyond_kib: u64,
    /// Each class apart. A file page that two classes map counts once in each, so these do not add
    /// up to the whole.
    pub classes: Vec<ClassReading>,
    /// Every file whose pages are resident in the group, the largest first.
    pub files: Vec<FileReading>,
}

impl Reading {
    /// The reading of one file, by the path its mappings are named with.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&FileReading> {
        self.files.iter().find(|file| file.path == path)
    }

    /// The figure the memory bound is held to: the pages in memory and the pages in swap.
    #[must_use]
    pub fn held_kib(&self) -> u64 {
        self.combined_kib + self.swapped_kib
    }

    /// The reading of one class.
    #[must_use]
    pub fn class(&self, name: &str) -> Option<&ClassReading> {
        self.classes.iter().find(|class| class.name == name)
    }

    /// The reading as the lines the reader prints and [`Reading::from_lines`] reads back.
    #[must_use]
    pub fn to_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "memory.group {} {} {} {} {} {} {}",
            self.processes,
            self.resident_kib,
            self.own_kib,
            self.files_kib,
            self.combined_kib,
            self.beyond_kib,
            self.swapped_kib
        )];
        for class in &self.classes {
            lines.push(format!(
                "memory.class {} {} {} {} {} {} {}",
                class.name,
                class.processes,
                class.resident_kib,
                class.own_kib,
                class.files_kib,
                class.combined_kib,
                class.swapped_kib
            ));
        }
        for file in &self.files {
            lines.push(format!(
                "memory.file {} {} {}",
                file.once_kib, file.each_kib, file.path
            ));
        }
        lines
    }

    /// Reads back what [`Reading::to_lines`] wrote, among other lines.
    ///
    /// # Errors
    ///
    /// A refusal the reader printed, or a result that is missing or does not read as numbers.
    pub fn from_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut group = None;
        let mut classes = Vec::new();
        let mut files = Vec::new();
        let mut ended = false;
        let numbers = |fields: &[&str]| -> Result<Vec<u64>, String> {
            fields
                .iter()
                .map(|field| {
                    field.parse().map_err(|_| {
                        format!("the reader's line has `{field}` where a number is due")
                    })
                })
                .collect()
        };
        for line in lines {
            if let Some(reason) = line.strip_prefix("memory.refused ") {
                return Err(reason.to_owned());
            }
            if line == "memory.end" {
                ended = true;
            } else if let Some(rest) = line.strip_prefix("memory.group ") {
                let fields: Vec<&str> = rest.split(' ').collect();
                let [
                    processes,
                    resident,
                    own,
                    files_kib,
                    combined,
                    beyond,
                    swapped,
                ] = numbers(&fields)?[..]
                else {
                    return Err("the reader's group line has the wrong number of fields".to_owned());
                };
                group = Some(Self {
                    processes: usize::try_from(processes).map_err(|_| "a count".to_owned())?,
                    resident_kib: resident,
                    own_kib: own,
                    files_kib,
                    combined_kib: combined,
                    swapped_kib: swapped,
                    beyond_kib: beyond,
                    classes: Vec::new(),
                    files: Vec::new(),
                });
            } else if let Some(rest) = line.strip_prefix("memory.class ") {
                let fields: Vec<&str> = rest.split(' ').collect();
                let [name, numeric @ ..] = &fields[..] else {
                    return Err("the reader's class line is empty".to_owned());
                };
                let [processes, resident, own, files_kib, combined, swapped] =
                    numbers(numeric)?[..]
                else {
                    return Err("the reader's class line has the wrong number of fields".to_owned());
                };
                classes.push(ClassReading {
                    name: (*name).to_owned(),
                    processes: usize::try_from(processes).map_err(|_| "a count".to_owned())?,
                    resident_kib: resident,
                    own_kib: own,
                    files_kib,
                    combined_kib: combined,
                    swapped_kib: swapped,
                });
            } else if let Some(rest) = line.strip_prefix("memory.file ") {
                let mut fields = rest.splitn(3, ' ');
                let (Some(once), Some(each), Some(path)) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Err("the reader's file line has the wrong number of fields".to_owned());
                };
                let [once_kib, each_kib] = numbers(&[once, each])?[..] else {
                    return Err("the reader's file line has the wrong sizes".to_owned());
                };
                files.push(FileReading {
                    path: path.to_owned(),
                    once_kib,
                    each_kib,
                });
            }
        }
        let mut reading = group.ok_or_else(|| "the reader printed no result".to_owned())?;
        if !ended {
            return Err("the reader's result ends before its last line".to_owned());
        }
        reading.classes = classes;
        reading.files = files;
        Ok(reading)
    }
}

/// How a scan of one process ended without a figure.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// The process's mappings changed while it was scanned: it may be scanned again.
    Changed(String),
    /// The process cannot be read, or its reading cannot be trusted: the whole reading is refused.
    Refused(String),
}

impl Failure {
    /// What went wrong, naming the process.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Changed(reason) | Self::Refused(reason) => reason,
        }
    }
}

/// Scans again while a process's mappings change, at most [`ATTEMPTS`] times in all, and stops at
/// once for any other failure.
///
/// # Errors
///
/// The refusal that ended the scans, or, when every attempt found the mappings changed, the last
/// change as a refusal.
pub fn with_retries<T>(mut scan: impl FnMut() -> Result<T, Failure>) -> Result<T, String> {
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        match scan() {
            Ok(done) => return Ok(done),
            Err(Failure::Changed(reason)) => last = reason,
            Err(Failure::Refused(reason)) => return Err(reason),
        }
    }
    Err(format!("{last}, and still after {ATTEMPTS} scans"))
}

/// Whether a scan's resident pages agree with the kernel's own resident size, and how far above it
/// they are.
///
/// A scan that finds fewer pages than the kernel by more than the larger of 64 KiB and one per cent
/// has lost some. One that finds more is accepted, and the difference is returned.
///
/// # Errors
///
/// The scan found too few pages.
pub fn agreement(pid: u32, found_kib: u64, kernel_kib: u64) -> Result<u64, String> {
    let tolerance = LEAST_TOLERANCE_KIB.max(kernel_kib / 100);
    if found_kib + tolerance < kernel_kib {
        return Err(format!(
            "process {pid}: the scan found {found_kib} KiB resident and the kernel reports \
             {kernel_kib} KiB"
        ));
    }
    Ok(found_kib.saturating_sub(kernel_kib))
}

/// One line of a process's `maps`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Mapping {
    start: u64,
    end: u64,
    /// The offset into the file the mapping starts at, in bytes.
    offset: u64,
    /// The device and inode of the file, as the kernel names them.
    device: String,
    inode: u64,
    path: String,
}

impl Mapping {
    /// Whether the pages of this mapping that the kernel marks as file pages are pages of a file that
    /// other processes can map too. A mapping with no inode is not, and neither is one of the
    /// kernel's own objects (an `anon_inode:` file), whose inode number does not name a file whose
    /// pages are shared: its pages count for the process.
    fn pages_are_of_a_shared_file(&self) -> bool {
        self.inode != 0 && !self.path.starts_with("anon_inode:")
    }

    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.splitn(6, ' ');
        let span = fields.next()?;
        let _permissions = fields.next()?;
        let offset = fields.next()?;
        let device = fields.next()?;
        let inode = fields.next()?;
        let path = fields.next().unwrap_or("").trim().to_owned();
        let (start, end) = span.split_once('-')?;
        Some(Self {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
            offset: u64::from_str_radix(offset, 16).ok()?,
            device: device.to_owned(),
            inode: inode.parse().ok()?,
            path,
        })
    }
}

/// A page of a file: its device, inode and page number in the file.
type FilePage = (String, u64, u64);

/// What one scan of one process found.
struct Scan {
    /// The pages found resident.
    resident: u64,
    /// The pages found in swap.
    swapped: u64,
    /// The pages that count for this process alone.
    own: u64,
    /// The file pages it maps.
    files: HashSet<FilePage>,
    /// For each file it maps: its path and how many of its pages are resident here.
    by_file: HashMap<(String, u64), (String, u64)>,
    /// How far above the kernel's resident size the scan is, in kibibytes.
    beyond_kib: u64,
}

/// A `/proc` directory and the page size its page maps are indexed by.
pub struct Proc {
    root: PathBuf,
    page_bytes: u64,
}

impl Proc {
    /// The tree at `root`, whose page maps hold one entry for each `page_bytes` of address space.
    /// The live tree is `/proc`; a check builds a stand-in from files it writes.
    #[must_use]
    pub fn at(root: impl Into<PathBuf>, page_bytes: u64) -> Self {
        Self {
            root: root.into(),
            page_bytes,
        }
    }

    /// This host's `/proc`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn system() -> Self {
        Self::at("/proc", rustix::param::page_size() as u64)
    }

    fn file(&self, pid: u32, name: &str) -> PathBuf {
        self.root.join(pid.to_string()).join(name)
    }

    fn read_text(&self, pid: u32, name: &str) -> Result<String, Failure> {
        std::fs::read_to_string(self.file(pid, name)).map_err(|error| {
            Failure::Refused(format!("process {pid}: reading its {name}: {error}"))
        })
    }

    /// The process's start time, which names the process the scan began with.
    fn started(&self, pid: u32) -> Result<String, Failure> {
        let stat = self.read_text(pid, "stat")?;
        // The command name is in parentheses and can hold spaces and parentheses of its own, so the
        // fields are counted from after the last parenthesis: the state is the first of them and the
        // start time the twentieth.
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .map(str::to_owned)
            .ok_or_else(|| Failure::Refused(format!("process {pid}: its stat has no start time")))
    }

    fn mappings(&self, pid: u32) -> Result<Vec<Mapping>, Failure> {
        self.read_text(pid, "maps")?
            .lines()
            .map(|line| {
                Mapping::parse(line).ok_or_else(|| {
                    Failure::Refused(format!("process {pid}: a mapping reads `{line}`"))
                })
            })
            .collect()
    }

    fn rss_kib(&self, pid: u32) -> Result<u64, Failure> {
        self.read_text(pid, "smaps_rollup")?
            .lines()
            .find_map(|line| line.strip_prefix("Rss:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kib| kib.parse().ok())
            .ok_or_else(|| Failure::Refused(format!("process {pid}: smaps_rollup has no Rss")))
    }

    /// One pass over one process.
    fn scan(&self, pid: u32) -> Result<Scan, Failure> {
        let before = self.started(pid)?;
        let listing = self.mappings(pid)?;
        let pagemap = File::open(self.file(pid, "pagemap")).map_err(|error| {
            Failure::Refused(format!("process {pid}: opening its page map: {error}"))
        })?;
        let mut scan = Scan {
            resident: 0,
            swapped: 0,
            own: 0,
            files: HashSet::new(),
            by_file: HashMap::new(),
            beyond_kib: 0,
        };
        let mut buffer = vec![0_u8; usize::try_from(CHUNK_PAGES * 8).unwrap_or(usize::MAX)];
        for mapping in &listing {
            if mapping.path == UNREADABLE_BY_DESIGN {
                continue;
            }
            let first = mapping.start / self.page_bytes;
            let pages = (mapping.end - mapping.start) / self.page_bytes;
            let mut done = 0;
            while done < pages {
                let count = CHUNK_PAGES.min(pages - done);
                let bytes = &mut buffer[..usize::try_from(count * 8).unwrap_or(0)];
                pagemap
                    .read_exact_at(bytes, (first + done) * 8)
                    .map_err(|error| {
                        let what = if error.kind() == std::io::ErrorKind::UnexpectedEof {
                            "a short read of"
                        } else {
                            "reading"
                        };
                        Failure::Refused(format!(
                            "process {pid}: {what} the page map of {}: {error}",
                            if mapping.path.is_empty() {
                                format!("{:#x}", mapping.start)
                            } else {
                                mapping.path.clone()
                            }
                        ))
                    })?;
                for (index, entry) in bytes.chunks_exact(8).enumerate() {
                    let entry = u64::from_ne_bytes(entry.try_into().unwrap_or([0; 8]));
                    if entry & PRESENT == 0 {
                        if entry & SWAPPED != 0 {
                            scan.swapped += 1;
                        }
                        continue;
                    }
                    scan.resident += 1;
                    if entry & FILE_OR_SHARED != 0 && mapping.pages_are_of_a_shared_file() {
                        let page = mapping.offset / self.page_bytes + done + index as u64;
                        scan.files
                            .insert((mapping.device.clone(), mapping.inode, page));
                        scan.by_file
                            .entry((mapping.device.clone(), mapping.inode))
                            .or_insert_with(|| (mapping.path.clone(), 0))
                            .1 += 1;
                    } else {
                        scan.own += 1;
                    }
                }
                done += count;
            }
        }
        if self.started(pid)? != before {
            return Err(Failure::Refused(format!(
                "process {pid} is not the process the scan began with"
            )));
        }
        if self.mappings(pid)? != listing {
            return Err(Failure::Changed(format!(
                "process {pid}: its mappings changed during the scan"
            )));
        }
        let found_kib = scan.resident * self.page_bytes / 1024;
        scan.beyond_kib =
            agreement(pid, found_kib, self.rss_kib(pid)?).map_err(Failure::Refused)?;
        Ok(scan)
    }

    /// Reads every process of every class, or refuses with the first reason that a process could
    /// not be read.
    ///
    /// # Errors
    ///
    /// A process that cannot be read whole, named with what failed.
    pub fn read(&self, classes: &[Class]) -> Result<Reading, String> {
        let kib = |pages: u64| pages * self.page_bytes / 1024;
        let mut whole: HashSet<FilePage> = HashSet::new();
        let mut each_by_file: HashMap<(String, u64), (String, u64)> = HashMap::new();
        let mut kinds = Vec::new();
        let mut resident = 0;
        let mut swapped = 0;
        let mut own = 0;
        let mut beyond_kib = 0;
        let mut processes = 0;
        for class in classes {
            let mut within: HashSet<FilePage> = HashSet::new();
            let mut class_resident = 0;
            let mut class_swapped = 0;
            let mut class_own = 0;
            for &pid in &class.pids {
                let scan = with_retries(|| self.scan(pid)).map_err(|reason| {
                    format!("{reason} (a process of the {} class)", class.name)
                })?;
                processes += 1;
                class_resident += scan.resident;
                class_swapped += scan.swapped;
                class_own += scan.own;
                beyond_kib += scan.beyond_kib;
                for (file, (path, pages)) in scan.by_file {
                    each_by_file.entry(file).or_insert_with(|| (path, 0)).1 += pages;
                }
                within.extend(scan.files.iter().cloned());
                whole.extend(scan.files);
            }
            resident += class_resident;
            swapped += class_swapped;
            own += class_own;
            kinds.push(ClassReading {
                name: class.name.clone(),
                processes: class.pids.len(),
                resident_kib: kib(class_resident),
                own_kib: kib(class_own),
                files_kib: kib(within.len() as u64),
                combined_kib: kib(class_own + within.len() as u64),
                swapped_kib: kib(class_swapped),
            });
        }
        let mut once_by_file: BTreeMap<(String, u64), u64> = BTreeMap::new();
        for (device, inode, _) in &whole {
            *once_by_file.entry((device.clone(), *inode)).or_insert(0) += 1;
        }
        let mut files: Vec<FileReading> = once_by_file
            .into_iter()
            .filter_map(|(file, once)| {
                let (path, each) = each_by_file.remove(&file)?;
                let path = if path.is_empty() {
                    format!("inode {} on {}", file.1, file.0)
                } else {
                    path
                };
                Some(FileReading {
                    path,
                    once_kib: kib(once),
                    each_kib: kib(each),
                })
            })
            .collect();
        files.sort_by(|left, right| {
            right
                .once_kib
                .cmp(&left.once_kib)
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok(Reading {
            processes,
            resident_kib: kib(resident),
            own_kib: kib(own),
            files_kib: kib(whole.len() as u64),
            combined_kib: kib(own + whole.len() as u64),
            swapped_kib: kib(swapped),
            beyond_kib,
            classes: kinds,
            files,
        })
    }
}

/// The classes as the reader's environment variable carries them: `name:pid,pid;name:pid`.
#[must_use]
pub fn classes_to_spec(classes: &[Class]) -> String {
    classes
        .iter()
        .map(|class| {
            let pids: Vec<String> = class.pids.iter().map(u32::to_string).collect();
            format!("{}:{}", class.name, pids.join(","))
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// The classes a spec names.
///
/// # Errors
///
/// A spec that is not in the form [`classes_to_spec`] writes.
pub fn classes_from_spec(spec: &str) -> Result<Vec<Class>, String> {
    spec.split(';')
        .map(|class| {
            let (name, pids) = class
                .split_once(':')
                .ok_or_else(|| format!("the class `{class}` has no processes"))?;
            let pids = pids
                .split(',')
                .filter(|pid| !pid.is_empty())
                .map(|pid| {
                    pid.parse()
                        .map_err(|_| format!("`{pid}` is not a process identifier"))
                })
                .collect::<Result<Vec<u32>, String>>()?;
            Ok(Class {
                name: name.to_owned(),
                pids,
            })
        })
        .collect()
}

/// The reader's part: when [`ROLE`] is set in this process's environment, reads the classes it
/// names from this host's `/proc`, prints the reading on lines of their own, and returns `true`.
/// A refusal is printed as one line and is also a result.
#[cfg(target_os = "linux")]
#[must_use]
pub fn serve_if_asked() -> bool {
    use std::io::Write as _;

    let Some(spec) = std::env::var_os(ROLE) else {
        return false;
    };
    let reading = classes_from_spec(&spec.to_string_lossy())
        .and_then(|classes| Proc::system().read(&classes));
    let mut lines = match reading {
        Ok(reading) => reading.to_lines(),
        Err(reason) => vec![format!("memory.refused {}", reason.replace('\n', " "))],
    };
    lines.push("memory.end".to_owned());
    // On lines of their own: the harness has already begun a line for the test that runs this.
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\n{}\n", lines.join("\n"));
    let _ = out.flush();
    true
}

/// A child process, watched through a pidfd that is opened the moment it starts (Linux).
///
/// Every wait on a child in this module is a `poll` on its pidfd with a deadline, so none can block
/// without a bound, whatever state the child is in; a signal goes by the pidfd, so it cannot reach a
/// process that was given the identifier after the child went; and the child is reaped
/// (`std::process::Child::wait`) only after the pidfd has said it exited, so that call returns at
/// once. A child that is still there after a kill and its grace is left, not waited for.
#[cfg(target_os = "linux")]
pub struct Watched {
    child: std::process::Child,
    pidfd: Option<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl Watched {
    /// How long a child that has been killed has to exit.
    const GRACE: std::time::Duration = std::time::Duration::from_secs(10);

    /// Starts the command and opens a pidfd for the child. A kernel that gives none leaves the child
    /// unwatched: [`Watched::exited_within`] then says it has not exited, and nothing waits for it.
    ///
    /// # Errors
    ///
    /// The command does not start.
    pub fn spawn(command: &mut std::process::Command) -> std::io::Result<Self> {
        let child = command.spawn()?;
        let pidfd = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .and_then(|pid| {
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()
            });
        Ok(Self { child, pidfd })
    }

    /// The child, for its pipes.
    pub fn child(&mut self) -> &mut std::process::Child {
        &mut self.child
    }

    /// The child's identifier.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Whether the child has exited within `limit`. It is not reaped: a child that has exited is a
    /// zombie until [`Watched::reap`].
    #[must_use]
    pub fn exited_within(&self, limit: std::time::Duration) -> bool {
        let Some(pidfd) = &self.pidfd else {
            return false;
        };
        let end = std::time::Instant::now() + limit;
        loop {
            let left = end.saturating_duration_since(std::time::Instant::now());
            let timeout = rustix::event::Timespec {
                tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(left.subsec_nanos()),
            };
            let mut fds = [rustix::event::PollFd::new(
                pidfd,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                // The pidfd is readable once the process has exited.
                Ok(ready) if ready > 0 => return true,
                Ok(_) => return false,
                // A signal interrupted the wait: wait again for the time that is left.
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return false,
            }
        }
    }

    /// Sends the child SIGKILL by its pidfd, or by its identifier where no pidfd was given.
    pub fn kill(&mut self) {
        match &self.pidfd {
            Some(pidfd) => {
                let _ = rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL);
            }
            None => {
                let _ = self.child.kill();
            }
        }
    }

    /// Kills the child and waits for its exit for at most the grace, without reaping it; says
    /// whether it exited.
    pub fn kill_and_wait_for_exit(&mut self) -> bool {
        self.kill();
        self.exited_within(Self::GRACE)
    }

    /// The child's exit status, as words, once it has exited; `Child::wait` returns at once then.
    /// A child that has not exited is not waited for.
    pub fn reap(&mut self) -> String {
        if !self.exited_within(std::time::Duration::ZERO) {
            return "it had not exited".to_owned();
        }
        self.child
            .wait()
            .map_or_else(|error| error.to_string(), |status| status.to_string())
    }
}

#[cfg(target_os = "linux")]
impl Drop for Watched {
    fn drop(&mut self) {
        if self.kill_and_wait_for_exit() {
            let _ = self.child.wait();
        }
    }
}

/// Reads the classes from outside, in a child copy of this test's own program that runs the test
/// named `test` with [`ROLE`] set; that test must call `serve_if_asked` first. The child has 60
/// seconds from its start to its exit: one that has not exited by then is killed, and the reading
/// is refused.
///
/// # Errors
///
/// A refusal of the reader, or a child that does not start, cannot be watched, does not exit
/// inside the limit, or ends without its result.
#[cfg(target_os = "linux")]
pub fn read_in_child(test: &str, classes: &[Class]) -> Result<Reading, String> {
    use std::io::{BufRead as _, Read as _};
    use std::time::{Duration, Instant};

    let this = std::env::current_exe().map_err(|error| format!("this program's path: {error}"))?;
    let deadline = Instant::now() + READER_LIMIT;
    let mut child = Watched::spawn(
        std::process::Command::new(this)
            .args(["--exact", test, "--nocapture", "--test-threads", "1"])
            .env(ROLE, classes_to_spec(classes))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped()),
    )
    .map_err(|error| format!("the memory reader does not start: {error}"))?;
    let output = child
        .child()
        .stdout
        .take()
        .ok_or_else(|| "the memory reader has no output".to_owned())?;
    let mut errors = child
        .child()
        .stderr
        .take()
        .ok_or_else(|| "the memory reader has no error output".to_owned())?;
    // Both pipes are read to their ends on threads of their own, so that a child that writes a great
    // deal never waits on a full pipe, and the failure to read either is kept. Each reports on a
    // channel and is waited for by a deadline; no thread is joined, so one still reading a pipe is
    // left to end with the pipe.
    let (sending, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in std::io::BufReader::new(output).split(b'\n') {
            match line {
                Ok(line) => {
                    let line = String::from_utf8_lossy(&line).into_owned();
                    if line.starts_with("memory.") {
                        lines.push(line);
                    }
                }
                Err(error) => {
                    let _ =
                        sending.send(Err(format!("reading the memory reader's output: {error}")));
                    return;
                }
            }
        }
        let _ = sending.send(Ok(lines));
    });
    let (complaining, complaints) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = errors.read_to_end(&mut bytes);
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        if let Err(error) = read {
            text.push_str(&format!("\n(reading the error output failed: {error})"));
        }
        let _ = complaining.send(text);
    });
    let in_time = child.exited_within(deadline.saturating_duration_since(Instant::now()));
    let stopped = !in_time;
    let exited = in_time || child.kill_and_wait_for_exit();
    let status = if exited {
        child.reap()
    } else {
        "it did not exit even when killed, and is left".to_owned()
    };
    // The pipes end with the child; the wait is a bound on the unexpected, as when another process
    // was given the other end of one.
    let grace = Duration::from_secs(10);
    let lines = received.recv_timeout(grace);
    let complaints = complaints.recv_timeout(grace).unwrap_or_default();
    let tail = complaints
        .lines()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ");
    if stopped {
        return Err(format!(
            "the memory reader did not exit within {READER_LIMIT:?} and was stopped ({status}); \
             its error output ends: {tail}"
        ));
    }
    match lines {
        Ok(Ok(lines)) if lines.iter().any(|line| line == "memory.end") => {
            Reading::from_lines(lines.iter().map(String::as_str))
        }
        Ok(Ok(_)) => Err(format!(
            "the memory reader gave no result: no test named `{test}` ran, or the reader stopped \
             before its result ({status}); its error output ends: {tail}"
        )),
        Ok(Err(reason)) => Err(format!(
            "{reason} ({status}); its error output ends: {tail}"
        )),
        Err(_) => Err(format!(
            "the memory reader's output did not end after its exit ({status}); its error output \
             ends: {tail}"
        )),
    }
}

/// The path a mapping of this host's own program is named by: what the kernel names it as.
#[cfg(target_os = "linux")]
#[must_use]
pub fn program_of(pid: u32) -> Option<String> {
    std::fs::read_link(
        std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("exe"),
    )
    .ok()
    .map(|path| path.to_string_lossy().into_owned())
}

/// The environment variable that makes a copy of the test's program hold memory and wait: its value
/// is how many mebibytes to hold and, after a comma, how (`written`, `read` or `undumpable`; see
/// [`Hold`]).
#[cfg(target_os = "linux")]
pub const HOLDER_ROLE: &str = "KR_PERF_MEMORY_HOLDER";

/// How a holding process holds its memory.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// It writes every page, so the pages are its own.
    Written,
    /// It reads fresh memory it never wrote: the kernel maps its shared zero page, which a resident
    /// size leaves out.
    Read,
    /// It writes every page and then refuses its page map to every reader.
    Undumpable,
}

#[cfg(target_os = "linux")]
impl Hold {
    fn name(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Read => "read",
            Self::Undumpable => "undumpable",
        }
    }
}

/// The holder's part: when [`HOLDER_ROLE`] is set, holds that much memory as it says, says `held` on a
/// line of its own, and waits until its input closes, so that it is read while it is still running.
/// Returns `true` when it was the holder.
#[cfg(target_os = "linux")]
#[must_use]
pub fn hold_if_asked() -> bool {
    use std::io::{BufRead as _, Write as _};

    let Some(spec) = std::env::var_os(HOLDER_ROLE) else {
        return false;
    };
    let spec = spec.to_string_lossy().into_owned();
    let (mebibytes, how) = spec.split_once(',').unwrap_or((spec.as_str(), "written"));
    let bytes = mebibytes.parse::<usize>().unwrap_or(0) * 1024 * 1024;
    let mut held = vec![0_u8; bytes];
    if how == "read" {
        // A fresh allocation of this size is fresh zero pages from the kernel; reading them maps the
        // shared zero page and makes none of them the process's own.
        let total: u64 = held.iter().map(|byte| u64::from(*byte)).sum();
        std::hint::black_box(total);
    } else {
        // Written, not only allocated: an untouched page of a new allocation is not resident.
        for (index, byte) in held.iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap_or(0);
        }
    }
    if how == "undumpable" {
        let _ =
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
    }
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\nheld\n");
    let _ = out.flush();
    drop(out);
    let _ = std::io::stdin().lock().read_line(&mut String::new());
    std::hint::black_box(&held);
    true
}

/// A copy of the test's program that is holding memory, for as long as this value lives.
#[cfg(target_os = "linux")]
pub struct Holder {
    child: Watched,
}

#[cfg(target_os = "linux")]
impl Holder {
    /// Starts a copy of this program that runs the test named `test`, which must call
    /// [`hold_if_asked`], and waits until it holds its memory.
    ///
    /// # Errors
    ///
    /// A copy that does not start or does not say it holds its memory inside the limit.
    pub fn spawn(test: &str, mebibytes: usize, how: Hold) -> Result<Self, String> {
        use std::io::{BufRead as _, Read as _};

        let this =
            std::env::current_exe().map_err(|error| format!("this program's path: {error}"))?;
        let mut child = Watched::spawn(
            std::process::Command::new(this)
                .args(["--exact", test, "--nocapture", "--test-threads", "1"])
                .env(HOLDER_ROLE, format!("{mebibytes},{}", how.name()))
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
        )
        .map_err(|error| format!("the holding process does not start: {error}"))?;
        let output = child
            .child()
            .stdout
            .take()
            .ok_or_else(|| "the holding process has no output".to_owned())?;
        let mut errors = child
            .child()
            .stderr
            .take()
            .ok_or_else(|| "the holding process has no error output".to_owned())?;
        let (complaining, complaints) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = errors.read_to_end(&mut bytes);
            let _ = complaining.send(String::from_utf8_lossy(&bytes).into_owned());
        });
        let (sending, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(output)
                .lines()
                .map_while(Result::ok)
            {
                if line == "held" {
                    let _ = sending.send(());
                    return;
                }
            }
        });
        match received.recv_timeout(READER_LIMIT) {
            Ok(()) => Ok(Self { child }),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "the holding process did not say it held its memory within {READER_LIMIT:?}"
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Its output ended: it has exited or is about to.
                let status = if child.kill_and_wait_for_exit() {
                    child.reap()
                } else {
                    "it did not exit even when killed".to_owned()
                };
                let complaints = complaints
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap_or_default();
                let tail = complaints
                    .lines()
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ");
                Err(format!(
                    "the holding process ended without saying it held its memory: no test named \
                     `{test}` ran, or it stopped before it held its memory ({status}); its error \
                     output ends: {tail}"
                ))
            }
        }
    }

    /// The process's identifier.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Ends the process and waits until it has exited without reaping it, which leaves it a zombie,
    /// and returns its identifier. The process is reaped when the holder is dropped.
    ///
    /// # Errors
    ///
    /// The process did not exit.
    pub fn end_unreaped(&mut self) -> Result<u32, String> {
        if self.child.kill_and_wait_for_exit() {
            Ok(self.child.id())
        } else {
            Err("the holding process did not exit when killed".to_owned())
        }
    }
}
