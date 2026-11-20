//! What keeps a program of the same account from the recovery seed while setup holds it, on
//! Windows.
//!
//! Windows lets a program of the account that owns a process open it for reading its memory, for a
//! dump, and for rewriting its own access list, whatever the process does. This module sets the
//! access lists that withhold those opens from later callers, and refuses to go on if any list
//! cannot be set or reads back other than it was set. The calls themselves are a trait, so the
//! order, the comparison and the refusals are the same code the cases run.
//!
//! # What is set, in this order
//!
//! 1. The process token is opened once, for the rights the next three steps need, and held to the
//!    end of the command. A handle on the token opened by a program of the account after step 4 has
//!    only the rights that list gives it.
//! 2. The token's *default list*: the list that every thread this process makes from now on is
//!    given. It is the thread list below, so a thread made after this step is protected from its
//!    first moment.
//! 3. The token object's own list: the owner and the account may read it and ask about it, and
//!    nobody may change what the process's later threads allow.
//! 4. Each of those lists is read back and compared with what was set.
//! 5. The process's list, read back the same way.
//! 6. The list of each thread the process has, found by a snapshot; a second snapshot then reads
//!    every thread's list and compares it, which covers a thread made during the first pass. A
//!    snapshot that ends for any reason but the system's word that no entry is left refuses.
//!
//! Every list names OWNER RIGHTS: an owner has the right to rewrite a list implicitly, and an
//! entry for OWNER RIGHTS replaces that. Every entry is compared by its type, flags, mask and
//! account, and not by the descriptor's control bits or the list's size, which differ between a
//! list that was set and one that was made as a default.
//!
//! # What follows from the default list
//!
//! The default list applies to every object this process makes after step 2, not only to its
//! threads, and as a process list it would lack the query right that the daemon's checks need.
//! After the protection setup therefore starts no process and makes no named object that another
//! program opens. A later change that needs such an object gives it a list of its own.

use std::io;

use kr_client::shown;
use kr_client::shown::{Said as _, Shown};

use crate::error::CliError;

/// `S-1-3-4`, the account that stands for whoever owns the object.
const OWNER_RIGHTS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
/// `S-1-5-18`, the system's account.
const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

const SYNCHRONIZE: u32 = 0x0010_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const TOKEN_QUERY: u32 = 0x0008;

/// What a process's list gives the owner and the account: to wait for it, to ask about it, to end
/// it, and to read its list. The daemon's peer check asks for no more.
pub const PROCESS_MASK: u32 =
    SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | READ_CONTROL;
/// What a thread's list gives them. The query right of a thread is `0x0800`, where the same right
/// of a process is `0x1000`, which as a thread right would let a thread be resumed.
pub const THREAD_MASK: u32 = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION | READ_CONTROL;
/// What the token object's list gives the account and the system.
pub const TOKEN_MASK: u32 = TOKEN_QUERY | READ_CONTROL;

/// One entry of an access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The entry's type; `0` is an allow entry.
    pub kind: u8,
    /// The entry's flags.
    pub flags: u8,
    /// The rights it names.
    pub mask: u32,
    /// The account it names, as the bytes of its identifier; for an entry of another type, the
    /// bytes after its header.
    pub account: Vec<u8>,
}

/// An access list: its entries in order, and nothing of the descriptor around it.
pub type List = Vec<Entry>;

fn allow(account: &[u8], mask: u32) -> Entry {
    Entry {
        kind: 0,
        flags: 0,
        mask,
        account: account.to_vec(),
    }
}

/// The list of every thread, and the token's default list.
#[must_use]
pub fn thread_list(account: &[u8]) -> List {
    vec![
        allow(&OWNER_RIGHTS, THREAD_MASK),
        allow(account, THREAD_MASK),
    ]
}

/// The list of the process.
#[must_use]
pub fn process_list(account: &[u8]) -> List {
    vec![
        allow(&OWNER_RIGHTS, PROCESS_MASK),
        allow(account, PROCESS_MASK),
    ]
}

/// The token object's own list.
#[must_use]
pub fn token_list(account: &[u8]) -> List {
    vec![
        allow(&OWNER_RIGHTS, READ_CONTROL),
        allow(account, TOKEN_MASK),
        allow(&SYSTEM, TOKEN_MASK),
    ]
}

/// The bytes of an access list that holds `list`, in the layout the system reads: a header, then
/// each allow entry followed by its account.
#[must_use]
pub fn acl_image(list: &[Entry]) -> Vec<u8> {
    let mut entries = Vec::new();
    for entry in list {
        let size = 8 + entry.account.len();
        let padded = size.div_ceil(4) * 4;
        entries.push(entry.kind);
        entries.push(entry.flags);
        entries.extend_from_slice(&u16::try_from(padded).unwrap_or(u16::MAX).to_le_bytes());
        entries.extend_from_slice(&entry.mask.to_le_bytes());
        entries.extend_from_slice(&entry.account);
        entries.resize(entries.len() + (padded - size), 0);
    }
    let size = 8 + entries.len();
    let mut image = vec![2, 0];
    image.extend_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_le_bytes());
    image.extend_from_slice(&u16::try_from(list.len()).unwrap_or(u16::MAX).to_le_bytes());
    image.extend_from_slice(&[0, 0]);
    image.extend_from_slice(&entries);
    image
}

/// The entries of the access list whose bytes are `image`, or nothing when the bytes are not a
/// list. Two lists with the same entries read the same however large their headers say they are.
#[must_use]
pub fn entries_of(image: &[u8]) -> Option<List> {
    let count = usize::from(u16::from_le_bytes([*image.get(4)?, *image.get(5)?]));
    let mut at = 8;
    let mut list = Vec::new();
    for _ in 0..count {
        let header = image.get(at..at + 4)?;
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let entry = image.get(at..at + size)?;
        let mask = if header[0] == 0 {
            u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?)
        } else {
            0
        };
        let account = &entry[8.min(entry.len())..];
        let account = if header[0] == 0 {
            // An identifier says how long it is, which drops the padding after it.
            let length = 8 + usize::from(*account.get(1)?) * 4;
            account.get(..length)?.to_vec()
        } else {
            account.to_vec()
        };
        list.push(Entry {
            kind: header[0],
            flags: header[1],
            mask,
            account,
        });
        at += size;
    }
    Some(list)
}

/// The values the two calls that suppress crash reports gave back: the error mode that was set
/// before, and the filter that stood before. Zero and null are values like others: neither is a
/// failure and neither is ever read as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Previous {
    /// The error mode that was set before.
    pub error_mode: u32,
    /// The address of the unhandled-exception filter that stood before, or zero.
    pub filter: usize,
}

/// What an open of a thread came to.
pub enum Open<T> {
    /// The thread, open.
    Opened(T),
    /// The system refused the open for want of access.
    Denied,
    /// There is no such thread now.
    Gone,
}

/// The calls the protection makes. The real ones are the system's; the cases give their own.
pub trait Calls {
    /// A thread, open.
    type Thread;

    /// The bytes of the identifier of the account that this process runs as.
    ///
    /// # Errors
    ///
    /// The system's error when the token cannot be read.
    fn account(&mut self) -> io::Result<Vec<u8>>;

    /// Makes the process end at once on an unhandled exception that reaches its filter, so that no
    /// report is made of it. It cannot refuse the setup.
    fn suppress_crash_reports(&mut self) -> Previous;

    /// Opens the process token and holds it until `self` is dropped.
    ///
    /// # Errors
    ///
    /// The system's error when the token cannot be opened.
    fn open_token(&mut self) -> io::Result<()>;

    /// Sets the token's default list.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn set_default_list(&mut self, list: &[Entry]) -> io::Result<()>;

    /// Reads the token's default list.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn default_list(&mut self) -> io::Result<List>;

    /// Sets the token object's own list, through the handle that [`Self::open_token`] holds.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn set_token_list(&mut self, list: &[Entry]) -> io::Result<()>;

    /// Reads the token object's own list.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn token_list(&mut self) -> io::Result<List>;

    /// Sets the process's list.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn set_process_list(&mut self, list: &[Entry]) -> io::Result<()>;

    /// Reads the process's list.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn process_list(&mut self) -> io::Result<List>;

    /// The identifiers of the threads this process has now.
    ///
    /// # Errors
    ///
    /// The system's error when the snapshot cannot be taken.
    fn thread_ids(&mut self) -> io::Result<Vec<u32>>;

    /// Opens the thread `id` to read its list, and for the change of it when `to_write`.
    ///
    /// # Errors
    ///
    /// The system's error for a failure that is neither a refusal nor a thread that is gone.
    fn open_thread(&mut self, id: u32, to_write: bool) -> io::Result<Open<Self::Thread>>;

    /// Whether `thread` belongs to this process: an identifier can be freed and taken again by a
    /// thread of another program between the snapshot and the open.
    ///
    /// # Errors
    ///
    /// The system's error when the question cannot be asked.
    fn thread_is_ours(&mut self, thread: &Self::Thread) -> io::Result<bool>;

    /// Sets the list of `thread`.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn set_thread_list(&mut self, thread: &Self::Thread, list: &[Entry]) -> io::Result<()>;

    /// Reads the list of `thread`.
    ///
    /// # Errors
    ///
    /// The system's error when the call fails.
    fn thread_list(&mut self, thread: &Self::Thread) -> io::Result<List>;

    /// Whether a debugger is attached to this process.
    fn debugger_present(&mut self) -> bool;
}

/// The system's error code for a snapshot that has no entry left to give.
const ERROR_NO_MORE_FILES: i32 = 18;

/// Whether a step through the entries of a snapshot gave an entry. `found` says the call returned
/// one, and when it did not, `code` is the system's last error, read at once after the call.
///
/// Only the system's word that no entry is left ends an enumeration as complete. Any other error
/// refuses, so that a pass that ended early never counts as one that saw every thread: two such
/// passes would admit a thread whose list was never set or read.
///
/// # Errors
///
/// The system's error when the call failed for a reason other than the end of the entries.
pub fn another_entry(found: bool, code: i32) -> io::Result<bool> {
    if found {
        Ok(true)
    } else if code == ERROR_NO_MORE_FILES {
        Ok(false)
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

/// Why the lists could not be set.
#[derive(Debug)]
pub enum Reason {
    /// A call failed, and the system said why.
    System(io::Error),
    /// A list read back other than it was set, and the words name which.
    NotAsSet(&'static str),
}

/// Why the protection refused to go on.
#[derive(Debug)]
pub enum Refusal {
    /// A list could not be set, or read back other than it was set.
    Lists(Reason),
    /// A debugger is attached to the process.
    Debugger,
}

impl Refusal {
    /// The failure of the command that this refusal ends.
    #[must_use]
    pub fn into_error(self) -> CliError {
        match self {
            Self::Lists(Reason::System(error)) => CliError::Other(shown!(
                "the recovery kit is not made because the access lists of this process could not \
                 be set: {}",
                Shown::io(&error)
            )),
            Self::Lists(Reason::NotAsSet(which)) => CliError::Other(shown!(
                "the recovery kit is not made because the access lists of this process could not \
                 be set: {}",
                Shown::said(which)
            )),
            Self::Debugger => CliError::Other(Shown::said(
                "the recovery kit is not made because a debugger is attached to this process",
            )),
        }
    }

    /// What the refusal says.
    #[must_use]
    pub fn words(self) -> String {
        self.into_error().said().as_str().to_owned()
    }
}

impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Self::Lists(Reason::System(error))
    }
}

/// The protection, in force: the token it holds stays open as long as this does.
#[must_use = "the token is held for as long as this is kept"]
pub struct Protected<C: Calls> {
    _calls: C,
}

/// Compares a list that was read back with the one that was set. A list that the system gave in a
/// form that is not an access list is a list that did not read back as set, and says so in the
/// words of its list; every other failure of the read is the system's own.
fn read_back(read: io::Result<List>, set: &[Entry], which: &'static str) -> Result<(), Refusal> {
    match read {
        Ok(list) if list == set => Ok(()),
        Ok(_) => Err(Refusal::Lists(Reason::NotAsSet(which))),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            Err(Refusal::Lists(Reason::NotAsSet(which)))
        }
        Err(error) => Err(error.into()),
    }
}

/// Makes the call on one thread of the first pass: its list is set, or a thread that the system
/// refused the change of is shown to hold the list that was meant, which is what a thread made
/// after the default list has.
fn protect_thread<C: Calls>(calls: &mut C, id: u32, list: &[Entry]) -> Result<(), Refusal> {
    match calls.open_thread(id, true)? {
        Open::Gone => Ok(()),
        Open::Opened(thread) => {
            if calls.thread_is_ours(&thread)? {
                calls.set_thread_list(&thread, list)?;
            }
            Ok(())
        }
        Open::Denied => match calls.open_thread(id, false)? {
            Open::Gone => Ok(()),
            Open::Denied => Err(Refusal::Lists(Reason::System(
                io::Error::from_raw_os_error(5),
            ))),
            Open::Opened(thread) => {
                if !calls.thread_is_ours(&thread)? {
                    return Ok(());
                }
                read_back(
                    calls.thread_list(&thread),
                    list,
                    "a thread's list was not as set",
                )
            }
        },
    }
}

/// The second pass over a thread: its list is read and compared, and nothing is set.
fn check_thread<C: Calls>(calls: &mut C, id: u32, list: &[Entry]) -> Result<(), Refusal> {
    match calls.open_thread(id, false)? {
        Open::Gone => Ok(()),
        Open::Denied => Err(Refusal::Lists(Reason::System(
            io::Error::from_raw_os_error(5),
        ))),
        Open::Opened(thread) => {
            if !calls.thread_is_ours(&thread)? {
                return Ok(());
            }
            read_back(
                calls.thread_list(&thread),
                list,
                "a thread's list was not as set",
            )
        }
    }
}

/// Protects this process from other programs of the account, in the order the module says, and
/// refuses with the words of the first failure.
///
/// # Errors
///
/// Returns the refusal when a call fails, when a list reads back other than it was set, or when a
/// debugger is attached once the lists are set.
pub fn apply<C: Calls>(mut calls: C) -> Result<Protected<C>, Refusal> {
    let account = calls.account()?;
    let threads = thread_list(&account);
    let token = token_list(&account);
    let process = process_list(&account);

    // The previous values are not looked at: a zero or a null is a value, never a failure.
    let _ = calls.suppress_crash_reports();

    calls.open_token()?;
    calls.set_default_list(&threads)?;
    calls.set_token_list(&token)?;
    read_back(
        calls.default_list(),
        &threads,
        "the token's default list was not as set",
    )?;
    read_back(
        calls.token_list(),
        &token,
        "the token's own list was not as set",
    )?;
    calls.set_process_list(&process)?;
    read_back(
        calls.process_list(),
        &process,
        "the process's list was not as set",
    )?;

    for id in calls.thread_ids()? {
        protect_thread(&mut calls, id, &threads)?;
    }
    for id in calls.thread_ids()? {
        check_thread(&mut calls, id, &threads)?;
    }

    if calls.debugger_present() {
        return Err(Refusal::Debugger);
    }
    Ok(Protected { _calls: calls })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const ACCOUNT: [u8; 28] = [
        1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 233, 3, 0, 0,
    ];

    /// How a thread of the fake answers.
    #[derive(Clone)]
    struct Behaviour {
        /// What the open to write gives.
        write: &'static str,
        /// What the open to read gives.
        read: &'static str,
        ours: bool,
        /// The list the thread holds whatever was set on it, for a thread changed by another
        /// program; none for a thread that holds what was set on it, and holds another list
        /// until one is set.
        holds: Option<List>,
    }

    fn the_list_set() -> List {
        thread_list(&ACCOUNT)
    }

    fn ordinary() -> Behaviour {
        Behaviour {
            write: "opened",
            read: "opened",
            ours: true,
            holds: None,
        }
    }

    /// The system, as the cases give it.
    struct Fake {
        log: Vec<String>,
        threads: Vec<u32>,
        behaviour: HashMap<u32, Behaviour>,
        /// The call that fails, by name.
        fails: Option<&'static str>,
        /// A call that fails only at its nth making, by name and count from one.
        fails_at: Option<(&'static str, usize)>,
        /// What a list reads back as, by name, in place of what was set.
        reads_as: HashMap<&'static str, List>,
        set: HashMap<&'static str, List>,
        /// The lists that read back in a form that is not an access list, by name.
        unparsable: Vec<&'static str>,
        /// The list that each thread was given, by identifier.
        set_threads: HashMap<u32, List>,
        debugger: bool,
        previous: Previous,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                log: Vec::new(),
                threads: vec![10, 11, 12],
                behaviour: HashMap::new(),
                fails: None,
                fails_at: None,
                reads_as: HashMap::new(),
                set: HashMap::new(),
                unparsable: Vec::new(),
                set_threads: HashMap::new(),
                debugger: false,
                previous: Previous {
                    error_mode: 0,
                    filter: 0,
                },
            }
        }

        fn call(&mut self, name: &'static str) -> io::Result<()> {
            self.log.push(name.to_owned());
            let times = self.log.iter().filter(|logged| *logged == name).count();
            if self.fails == Some(name) || self.fails_at == Some((name, times)) {
                Err(io::Error::from_raw_os_error(1_450))
            } else {
                Ok(())
            }
        }

        fn behaviour_of(&self, id: u32) -> Behaviour {
            self.behaviour.get(&id).cloned().unwrap_or_else(ordinary)
        }

        fn read(&self, name: &'static str) -> io::Result<List> {
            if self.unparsable.contains(&name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "an access list that is not a list",
                ));
            }
            Ok(self
                .reads_as
                .get(name)
                .or_else(|| self.set.get(name))
                .cloned()
                .unwrap_or_default())
        }
    }

    impl Calls for Fake {
        type Thread = u32;

        fn account(&mut self) -> io::Result<Vec<u8>> {
            Ok(ACCOUNT.to_vec())
        }

        fn suppress_crash_reports(&mut self) -> Previous {
            self.log.push("suppress".to_owned());
            self.previous
        }

        fn open_token(&mut self) -> io::Result<()> {
            self.call("open token")
        }

        fn set_default_list(&mut self, list: &[Entry]) -> io::Result<()> {
            self.set.insert("default", list.to_vec());
            self.call("set default")
        }

        fn default_list(&mut self) -> io::Result<List> {
            self.call("read default")?;
            self.read("default")
        }

        fn set_token_list(&mut self, list: &[Entry]) -> io::Result<()> {
            self.set.insert("token", list.to_vec());
            self.call("set token")
        }

        fn token_list(&mut self) -> io::Result<List> {
            self.call("read token")?;
            self.read("token")
        }

        fn set_process_list(&mut self, list: &[Entry]) -> io::Result<()> {
            self.set.insert("process", list.to_vec());
            self.call("set process")
        }

        fn process_list(&mut self) -> io::Result<List> {
            self.call("read process")?;
            self.read("process")
        }

        fn thread_ids(&mut self) -> io::Result<Vec<u32>> {
            self.call("snapshot")?;
            Ok(self.threads.clone())
        }

        fn open_thread(&mut self, id: u32, to_write: bool) -> io::Result<Open<u32>> {
            self.log.push(format!(
                "open {id} {}",
                if to_write { "write" } else { "read" }
            ));
            let behaviour = self.behaviour_of(id);
            let answer = if to_write {
                behaviour.write
            } else {
                behaviour.read
            };
            match answer {
                "opened" => Ok(Open::Opened(id)),
                "denied" => Ok(Open::Denied),
                "gone" => Ok(Open::Gone),
                _ => Err(io::Error::from_raw_os_error(1_450)),
            }
        }

        fn thread_is_ours(&mut self, thread: &u32) -> io::Result<bool> {
            Ok(self.behaviour_of(*thread).ours)
        }

        fn set_thread_list(&mut self, thread: &u32, list: &[Entry]) -> io::Result<()> {
            self.call("set thread")?;
            self.log.push(format!("set {thread}"));
            self.set_threads.insert(*thread, list.to_vec());
            Ok(())
        }

        fn thread_list(&mut self, thread: &u32) -> io::Result<List> {
            self.log.push(format!("read {thread}"));
            if self.unparsable.contains(&"thread") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "an access list that is not a list",
                ));
            }
            Ok(self.behaviour_of(*thread).holds.unwrap_or_else(|| {
                // A thread holds what was set on it, and another list until then.
                self.set_threads
                    .get(thread)
                    .cloned()
                    .unwrap_or_else(|| vec![allow(&ACCOUNT, 0x001F_FFFF)])
            }))
        }

        fn debugger_present(&mut self) -> bool {
            self.log.push("debugger".to_owned());
            self.debugger
        }
    }

    fn position(log: &[String], call: &str) -> usize {
        log.iter()
            .position(|logged| logged == call)
            .unwrap_or_else(|| panic!("{call} was not made: {log:?}"))
    }

    /// The calls come in the order of the module's text, and each list that is passed to the system
    /// is the one that was meant: the owner and the account only, with the process, thread and
    /// token masks, each compared whole with the entries written out here.
    #[test]
    fn the_lists_are_set_in_order_and_each_is_the_one_that_was_meant() {
        let mut fake = Fake::new();
        fake.threads = vec![10];
        let Ok(held) = apply(fake) else {
            panic!("the protection was meant to hold");
        };
        let fake = held._calls;
        let log = fake.log.clone();
        let order = [
            "suppress",
            "open token",
            "set default",
            "set token",
            "read default",
            "read token",
            "set process",
            "read process",
            "snapshot",
            "set 10",
            "snapshot",
            "read 10",
            "debugger",
        ];
        let mut at = 0;
        for call in order {
            let found = log[at..].iter().position(|logged| logged == call);
            assert!(found.is_some(), "{call} comes after position {at}: {log:?}");
            at += found.unwrap_or(0) + 1;
        }

        // What each list passed to the system holds, entry by entry: type, flags, mask and account.
        let thread = vec![
            allow(&OWNER_RIGHTS, 0x0012_0800),
            allow(&ACCOUNT, 0x0012_0800),
        ];
        assert_eq!(fake.set.get("default"), Some(&thread));
        assert_eq!(fake.set_threads.get(&10), Some(&thread));
        assert_eq!(
            fake.set.get("token"),
            Some(&vec![
                allow(&OWNER_RIGHTS, 0x0002_0000),
                allow(&ACCOUNT, 0x0002_0008),
                allow(&SYSTEM, 0x0002_0008),
            ]),
            "the owner may only read the list; the account and the system query and read it"
        );
        assert_eq!(
            fake.set.get("process"),
            Some(&vec![
                allow(&OWNER_RIGHTS, 0x0012_1001),
                allow(&ACCOUNT, 0x0012_1001),
            ]),
            "wait, ask, end, read the list"
        );
        assert_eq!(THREAD_MASK, 0x0012_0800, "wait, ask, read the list");
        assert_eq!(PROCESS_MASK, 0x0012_1001, "wait, ask, end, read the list");
    }

    /// Hands the fake's log out once the protection is done with it.
    struct Recorder<'a>(&'a mut Option<Vec<String>>, Fake);

    impl Drop for Recorder<'_> {
        fn drop(&mut self) {
            *self.0 = Some(std::mem::take(&mut self.1.log));
        }
    }

    impl Calls for Recorder<'_> {
        type Thread = u32;

        fn account(&mut self) -> io::Result<Vec<u8>> {
            self.1.account()
        }
        fn suppress_crash_reports(&mut self) -> Previous {
            self.1.suppress_crash_reports()
        }
        fn open_token(&mut self) -> io::Result<()> {
            self.1.open_token()
        }
        fn set_default_list(&mut self, list: &[Entry]) -> io::Result<()> {
            self.1.set_default_list(list)
        }
        fn default_list(&mut self) -> io::Result<List> {
            self.1.default_list()
        }
        fn set_token_list(&mut self, list: &[Entry]) -> io::Result<()> {
            self.1.set_token_list(list)
        }
        fn token_list(&mut self) -> io::Result<List> {
            self.1.token_list()
        }
        fn set_process_list(&mut self, list: &[Entry]) -> io::Result<()> {
            self.1.set_process_list(list)
        }
        fn process_list(&mut self) -> io::Result<List> {
            self.1.process_list()
        }
        fn thread_ids(&mut self) -> io::Result<Vec<u32>> {
            self.1.thread_ids()
        }
        fn open_thread(&mut self, id: u32, to_write: bool) -> io::Result<Open<u32>> {
            self.1.open_thread(id, to_write)
        }
        fn thread_is_ours(&mut self, thread: &u32) -> io::Result<bool> {
            self.1.thread_is_ours(thread)
        }
        fn set_thread_list(&mut self, thread: &u32, list: &[Entry]) -> io::Result<()> {
            self.1.set_thread_list(thread, list)
        }
        fn thread_list(&mut self, thread: &u32) -> io::Result<List> {
            self.1.thread_list(thread)
        }
        fn debugger_present(&mut self) -> bool {
            self.1.debugger_present()
        }
    }

    /// A call that fails refuses with the system's own words, before any later call is made.
    #[test]
    fn a_failed_list_call_refuses_with_the_system_error_and_stops() {
        for (failing, later) in [
            ("open token", "set default"),
            ("set default", "set token"),
            ("set token", "read default"),
            ("set process", "read process"),
        ] {
            let mut fake = Fake::new();
            fake.fails = Some(failing);
            let mut kept = None;
            let Err(refusal) = apply(Recorder(&mut kept, fake)) else {
                panic!("{failing}: the protection held although a call failed");
            };
            let words = refusal.words();
            assert!(
                words.starts_with(
                    "the recovery kit is not made because the access lists of this process could \
                     not be set: "
                ),
                "{failing}: {words}"
            );
            assert!(words.contains("os error 1450"), "{failing}: {words}");
            let log = kept.expect("the log");
            assert!(
                !log.iter().any(|logged| logged == later),
                "{failing} stopped the calls: {log:?}"
            );
        }
    }

    /// A list that reads back other than it was set refuses, and the words name which list, with
    /// no system error from a call that succeeded. Each list has its case, which the read-back of
    /// that list alone can fail.
    #[test]
    fn a_list_that_reads_back_other_than_set_refuses_and_names_the_list() {
        let other = || vec![allow(&OWNER_RIGHTS, 0x001F_FFFF)];
        for (name, which) in [
            ("default", "the token's default list was not as set"),
            ("token", "the token's own list was not as set"),
            ("process", "the process's list was not as set"),
        ] {
            let mut fake = Fake::new();
            fake.reads_as.insert(name, other());
            let mut kept = None;
            let Err(refusal) = apply(Recorder(&mut kept, fake)) else {
                panic!("{name}: the protection held although the list read back other than set");
            };
            let words = refusal.words();
            assert_eq!(
                words,
                format!(
                    "the recovery kit is not made because the access lists of this process could \
                     not be set: {which}"
                ),
                "{name}"
            );
            let log = kept.expect("the log");
            assert!(
                !log.iter().any(|logged| logged == "debugger"),
                "{name}: nothing went on: {log:?}"
            );
        }

        // A list that the system gives in a form that is not a list did not read back as set
        // either, and names its list in the same words: no words of the system's own about a
        // format reach the person.
        for (name, which) in [
            ("default", "the token's default list was not as set"),
            ("token", "the token's own list was not as set"),
            ("process", "the process's list was not as set"),
            ("thread", "a thread's list was not as set"),
        ] {
            let mut fake = Fake::new();
            fake.unparsable.push(name);
            let mut kept = None;
            let Err(refusal) = apply(Recorder(&mut kept, fake)) else {
                panic!("{name}: the protection held although the list was not a list");
            };
            assert_eq!(
                refusal.words(),
                format!(
                    "the recovery kit is not made because the access lists of this process could \
                     not be set: {which}"
                ),
                "{name} unparsable"
            );
        }
    }

    /// A thread whose list the system refuses to change counts as protected only when its list
    /// reads as the one that was meant.
    #[test]
    fn a_thread_that_refuses_the_change_is_protected_only_by_an_equal_list() {
        let mut fake = Fake::new();
        fake.behaviour.insert(
            11,
            Behaviour {
                write: "denied",
                holds: Some(the_list_set()),
                ..ordinary()
            },
        );
        let mut kept = None;
        assert!(
            apply(Recorder(&mut kept, fake)).is_ok(),
            "an equal list is protected"
        );

        let mut fake = Fake::new();
        fake.behaviour.insert(
            11,
            Behaviour {
                write: "denied",
                holds: Some(vec![allow(&ACCOUNT, 0x001F_FFFF)]),
                ..ordinary()
            },
        );
        let Err(refusal) = apply(fake) else {
            panic!("a thread that reads back another list was protected");
        };
        let words = refusal.words();
        assert!(words.ends_with("a thread's list was not as set"), "{words}");

        let mut fake = Fake::new();
        fake.behaviour.insert(
            11,
            Behaviour {
                write: "denied",
                read: "denied",
                ..ordinary()
            },
        );
        let Err(refusal) = apply(fake) else {
            panic!("a thread that refuses both opens was protected");
        };
        let words = refusal.words();
        assert!(words.contains("os error 5"), "{words}");
    }

    /// A thread that is gone is skipped, and a thread that another program has taken the identifier
    /// of is counted as gone, with nothing set on it.
    #[test]
    fn a_thread_that_is_gone_or_belongs_to_another_process_is_skipped() {
        let mut fake = Fake::new();
        fake.behaviour.insert(
            10,
            Behaviour {
                write: "gone",
                read: "gone",
                ..ordinary()
            },
        );
        fake.behaviour.insert(
            11,
            Behaviour {
                ours: false,
                holds: Some(Vec::new()),
                ..ordinary()
            },
        );
        let mut kept = None;
        assert!(apply(Recorder(&mut kept, fake)).is_ok());
        let log = kept.expect("the log");
        assert!(
            !log.contains(&"set 11".to_owned()),
            "nothing set on another's thread: {log:?}"
        );
        assert!(!log.contains(&"read 11".to_owned()), "{log:?}");
        assert!(log.contains(&"set 12".to_owned()), "{log:?}");
    }

    /// A thread whose list differs at the second pass, such as one made during the first, refuses.
    #[test]
    fn a_thread_whose_list_differs_at_the_second_pass_refuses() {
        let mut fake = Fake::new();
        // Every open succeeds and the first pass sets the list, but the thread then reads back as
        // another list, as a thread would that was changed after the first pass.
        fake.behaviour.insert(
            12,
            Behaviour {
                holds: Some(vec![allow(&OWNER_RIGHTS, 0x001F_FFFF)]),
                ..ordinary()
            },
        );
        let Err(refusal) = apply(fake) else {
            panic!("a thread that reads back another list at the second pass was protected");
        };
        let words = refusal.words();
        assert!(words.ends_with("a thread's list was not as set"), "{words}");
    }

    /// Entries that are equal are equal whatever the header of the list that holds them says of
    /// its size: a list made as a default and one that was set differ there and nowhere else.
    #[test]
    fn lists_with_equal_entries_read_equal_whatever_their_headers_say() {
        let list = thread_list(&ACCOUNT);
        let image = acl_image(&list);
        assert_eq!(entries_of(&image), Some(list.clone()));

        let mut larger = image.clone();
        larger.extend_from_slice(&[0; 40]);
        let size = u16::try_from(larger.len()).unwrap().to_le_bytes();
        larger[2..4].copy_from_slice(&size);
        larger[1] = 9;
        assert_ne!(larger, image);
        assert_eq!(
            entries_of(&larger),
            Some(list),
            "the header's size and spare byte differ"
        );

        assert_eq!(
            entries_of(&image[..image.len() - 3]),
            None,
            "a cut list is not a list"
        );
        assert_eq!(entries_of(&[2, 0]), None);
    }

    /// A previous value of zero or null from the calls that suppress crash reports is no failure.
    #[test]
    fn a_previous_value_of_zero_or_null_is_not_a_failure() {
        let mut fake = Fake::new();
        fake.previous = Previous {
            error_mode: 0,
            filter: 0,
        };
        let mut kept = None;
        assert!(apply(Recorder(&mut kept, fake)).is_ok());
    }

    /// Only the end of the entries that the system names completes an enumeration: any other error
    /// is the system's error, so a pass cut short never reads as a whole one.
    #[test]
    fn only_the_systems_end_of_the_entries_ends_an_enumeration_as_complete() {
        assert_eq!(another_entry(true, 0).ok(), Some(true));
        assert_eq!(another_entry(true, 18).ok(), Some(true));
        assert_eq!(another_entry(false, 18).ok(), Some(false));
        for code in [0, 5, 6, 87, 1_450] {
            let Err(error) = another_entry(false, code) else {
                panic!("error {code} ended the enumeration as complete");
            };
            assert_eq!(error.raw_os_error(), Some(code));
        }
    }

    /// A snapshot that fails, before its first thread or after some, refuses with the system's
    /// words at the first pass and at the second, and nothing later is made: no list is read on a
    /// thread of a pass that did not see them all, and no debugger check is reached.
    #[test]
    fn a_snapshot_that_fails_refuses_at_either_pass_and_stops() {
        for (failing, later) in [(1, "set 10"), (2, "read 10")] {
            let mut fake = Fake::new();
            fake.threads = vec![10];
            fake.fails_at = Some(("snapshot", failing));
            let mut kept = None;
            let Err(refusal) = apply(Recorder(&mut kept, fake)) else {
                panic!("snapshot {failing} failed and the protection held");
            };
            let words = refusal.words();
            assert!(
                words.starts_with(
                    "the recovery kit is not made because the access lists of this process could \
                     not be set: "
                ),
                "snapshot {failing}: {words}"
            );
            assert!(
                words.contains("os error 1450"),
                "snapshot {failing}: {words}"
            );
            let log = kept.expect("the log");
            assert!(
                !log.iter()
                    .any(|logged| logged == later || logged == "debugger"),
                "snapshot {failing} stopped the calls: {log:?}"
            );
        }
    }

    /// A debugger refuses, in its own words, after the lists are set.
    #[test]
    fn a_debugger_refuses_in_its_own_words_after_the_lists_are_set() {
        let mut fake = Fake::new();
        fake.debugger = true;
        let mut kept = None;
        let Err(refusal) = apply(Recorder(&mut kept, fake)) else {
            panic!("a debugger was attached and the protection held");
        };
        let words = refusal.words();
        assert_eq!(
            words,
            "the recovery kit is not made because a debugger is attached to this process"
        );
        let log = kept.expect("the log");
        assert!(position(&log, "read process") < position(&log, "debugger"));
    }
}
