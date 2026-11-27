//! The application server a session starts for a native terminal, and how it is ended.
//!
//! A terminal that points itself at the worker's gateway speaks to one application server for the
//! session, a child of the worker on pipes. This is the starting of it and the ending of it, and
//! nothing between: what the server and the terminal say to each other is the gateway's.
//!
//! What every platform shares is here: what the server is started from, what the session records
//! below it ([`Owned`]), how an ending comes out ([`Retirement`], [`Ended`] and [`Emptiness`]), the
//! server's input, and the five seconds an ending has before anything in it is forced. How a server
//! is started and its tree ended is the platform's: a process group and signals on Unix, a job
//! object on Windows, whose ending is one function ([`end_tree`]) over what a job lets be read and
//! done to it ([`Tree`]).

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Waker;
use std::time::Duration;

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::Digest256;
use tokio::io::AsyncWrite;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{InputPipe, Output, Server};

/// How long the server has to end after its input has closed, before it is asked to terminate.
pub const INPUT_GRACE: Duration = Duration::from_millis(1500);

/// How long an ending lasts before anything in it is forced, counted from its beginning: the
/// grace a session gives the processes it owns.
pub const GRACE_WINDOW: Duration = crate::session::GRACE_PERIOD;

/// How long a process that was ended by force has to be gone: the drain a session gives after it
/// forces what it owns.
pub const FORCE_WAIT: Duration = crate::session::DRAIN_PERIOD;

/// How much of what the server writes to its error stream is kept: the last of it.
pub const MAX_ERROR_BYTES: usize = 64 * 1024;

/// The variables of the launch that are not given to the server: the launcher's registration and
/// its credential name the launch, and the server is not the launched program.
pub const WITHHELD_VARIABLES: [&str; 2] = kr_protocol::root::LAUNCH_VARIABLES;

/// What a session recorded of the processes below its servers, as the ending reads and changes it.
///
/// The session implements it over its record of the processes it owns.
///
/// The ending reads the record when it begins, after the server's input has had its grace, again
/// and again while the processes below the server end, before each round of force, and once more
/// at its end. The last reading only reports: a process that it shows for the first time is
/// returned as one that is still running, with no request to terminate and no force, because the
/// rounds of force are bounded and the ending cannot wait for another. The session's record can
/// show one when it recorded a child between two readings, below a parent that ended after the
/// earlier one, or below a process that outlived every round; the record keeps it, so the
/// closure's receipt names it among the survivors.
///
/// The ending of a server on Windows reads the server's own job instead, which holds every process
/// the server started, and uses the record only to note what it forced and what it could not end.
pub trait Owned: Send + Sync {
    /// Reads what runs below `server` now, and returns the processes recorded below it, the ones
    /// read earlier included, that have not been read as ended.
    fn below(&self, server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity>;

    /// Says whether `process` has left the session for a control daemon's own scope. Such a
    /// process is not the session's: the ending neither asks it to terminate nor forces it, and
    /// does not report it as still running. It is asked before every request and every force,
    /// because a reading that returned the process can be older than the one that read it leaving.
    /// A process recorded below one that left has left too, whichever of the two is asked about
    /// first.
    fn left(&self, process: &ProcessStartIdentity) -> bool;

    /// Notes that `process` was ended by force.
    fn forced(&self, process: &ProcessStartIdentity);

    /// Notes that `process` could not be signalled, and why: the system refused, or could not tell
    /// the process from a stranger that holds its number.
    fn unsignalled(&self, process: &ProcessStartIdentity, why: &str);
}

/// What the server is started from.
pub struct ServerSpec<'a> {
    /// The executable, as the launch presented it.
    pub executable: &'a Path,
    /// The digest a signed qualification record names for it.
    pub digest: &'a Digest256,
    /// The arguments the integration's backend declares.
    pub arguments: &'a [String],
    /// The directory the invocation works in.
    pub directory: &'a Path,
    /// The environment the launcher presented.
    pub presented: &'a [(OsString, OsString)],
}

impl std::fmt::Debug for ServerSpec<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The environment is the person's, and is never shown: only how many variables it holds.
        formatter
            .debug_struct("ServerSpec")
            .field("executable", &self.executable)
            .field("digest", &self.digest)
            .field("arguments", &self.arguments)
            .field("directory", &self.directory)
            .field(
                "presented",
                &format_args!("{} variables", self.presented.len()),
            )
            .finish()
    }
}

/// How the server came to an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It was gone before the ending began.
    Already,
    /// It ended when its input closed.
    Input,
    /// It ended when it was asked to terminate, within the window. A platform with no request to
    /// terminate never has this.
    Terminate,
    /// It was still running when the window was over, and was ended by force, or ended of itself
    /// as that was done.
    Force,
    /// It was still running when the ending was over: a signal was refused, or it did not end in
    /// the time a forced end is given. It is among the survivors.
    Alive,
}

/// Whether what a server started is all gone, as far as the ending could tell.
///
/// A conversation the server ran against is free for another session only when this is
/// [`Self::Empty`]: a process that may still be running could be writing to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emptiness {
    /// Nothing the server started is running: the tree was read and was empty.
    Empty,
    /// A process the server started is still running, and the survivors name it.
    Nonempty,
    /// The tree could not be read, or a process in it could not be asked about, so nothing can be
    /// said either way. It becomes [`Self::Empty`] only by a later reading that succeeds and finds
    /// nothing.
    Unknown,
}

impl Emptiness {
    /// What a reading by parentage found: the survivors are what is running, so the tree is empty
    /// when there are none and not otherwise. A reading by parentage never says it could not tell,
    /// and says so in its documentation.
    #[must_use]
    pub fn of_survivors(survivors: &[ProcessStartIdentity]) -> Self {
        if survivors.is_empty() {
            Self::Empty
        } else {
            Self::Nonempty
        }
    }
}

/// What ending a server came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retirement {
    /// How the server itself ended.
    pub ended: Ended,
    /// The processes that were ended by force, the server among them when it was.
    pub forced: Vec<ProcessStartIdentity>,
    /// The processes still running when the ending was over: the ones recorded below the server,
    /// and the server itself when it is [`Ended::Alive`].
    pub survivors: Vec<ProcessStartIdentity>,
    /// Whether anything the server started is still running.
    pub emptiness: Emptiness,
}

/// The server's input, which the connection writes to and the ending closes.
///
/// The connection owns what it writes through; the ending has to close the pipe whoever holds it,
/// so the pipe is shared, and closing it makes every later write fail and wakes a write that was
/// waiting. A shutdown of a holder's end closes it for every holder, which is the end of the
/// server's input.
#[derive(Debug)]
pub struct Input<W = InputPipe>(Arc<Mutex<InputState<W>>>);

impl<W> Clone for Input<W> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[derive(Debug)]
struct InputState<W> {
    pipe: Option<W>,
    /// The task whose write or flush is waiting, woken when the pipe is closed.
    waiting: Option<Waker>,
}

impl<W> Input<W> {
    pub(crate) fn new(pipe: Option<W>) -> Self {
        Self(Arc::new(Mutex::new(InputState {
            pipe,
            waiting: None,
        })))
    }

    /// Closes the pipe, for every holder.
    pub(crate) fn close(&self) {
        let (pipe, waiting) = {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            (state.pipe.take(), state.waiting.take())
        };
        drop(pipe);
        if let Some(waker) = waiting {
            waker.wake();
        }
    }

    fn with<T>(
        &self,
        cx: &mut std::task::Context<'_>,
        use_pipe: impl FnOnce(
            std::pin::Pin<&mut W>,
            &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<T>>,
    ) -> std::task::Poll<std::io::Result<T>>
    where
        W: Unpin,
    {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pipe) = state.pipe.as_mut() else {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        };
        let polled = use_pipe(std::pin::Pin::new(pipe), cx);
        if polled.is_pending() {
            state.waiting = Some(cx.waker().clone());
        }
        polled
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Input<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.with(cx, |pipe, cx| pipe.poll_write(cx, buffer))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.with(cx, |pipe, cx| pipe.poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.close();
        std::task::Poll::Ready(Ok(()))
    }
}

/// The last bytes of what a process wrote.
#[derive(Debug, Default)]
pub(crate) struct Tail(Mutex<VecDeque<u8>>);

impl Tail {
    pub(crate) fn push(&self, bytes: &[u8]) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        held.extend(bytes);
        let over = held.len().saturating_sub(MAX_ERROR_BYTES);
        held.drain(..over);
    }

    pub(crate) fn text(&self) -> String {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes: Vec<u8> = held.iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// How often a tree is read again while it is waited for.
#[cfg(any(windows, test))]
const TREE_REREAD: Duration = Duration::from_millis(20);

/// One process a tree holds, as a reading of the tree names it.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Member {
    /// The tree holds it, and this is its identity.
    Held(ProcessStartIdentity),
    /// The tree lists it and it could not be asked about, for the reason given.
    Unreadable(String),
}

/// What a server's tree lets the ending read and do: the processes the server's own job holds.
///
/// A platform whose server is held by a job implements this over the job, and the ending of the
/// tree is the one function [`end_tree`] over it; nothing in that function knows what a job is,
/// which is what lets a case run it against a tree that is a script and signals nothing.
#[cfg(any(windows, test))]
pub(crate) trait Tree: Send + Sync {
    /// Whether the server's own process is still running.
    fn root_running(&self) -> impl std::future::Future<Output = bool> + Send;

    /// Closes the server's input, for every holder.
    fn close_input(&self);

    /// Reads the processes the tree holds now: each as it is named, or why one could not be read,
    /// or why the tree could not be read at all.
    fn members(&self) -> impl std::future::Future<Output = Result<Vec<Member>, String>> + Send;

    /// Ends every process the tree holds, at once.
    fn terminate(&self) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// One reading of a tree, as the ending sorts it.
#[cfg(any(windows, test))]
enum Reading {
    /// The tree could not be read.
    Failed,
    /// The tree was read: the processes it holds, and whether it lists one it could not ask about.
    Seen {
        held: Vec<ProcessStartIdentity>,
        unreadable: bool,
    },
}

#[cfg(any(windows, test))]
impl Reading {
    async fn of(tree: &impl Tree) -> Self {
        match tree.members().await {
            Err(_) => Self::Failed,
            Ok(members) => {
                let mut held = Vec::new();
                let mut unreadable = false;
                for member in members {
                    match member {
                        Member::Held(process) => held.push(process),
                        Member::Unreadable(_) => unreadable = true,
                    }
                }
                Self::Seen { held, unreadable }
            }
        }
    }

    /// Whether the reading shows a tree with nothing in it: only a reading that succeeded and
    /// listed nothing does.
    const fn is_empty(&self) -> bool {
        matches!(self, Self::Seen { held, unreadable: false } if held.is_empty())
    }

    fn held(&self) -> Vec<ProcessStartIdentity> {
        match self {
            Self::Seen { held, .. } => held.clone(),
            Self::Failed => Vec::new(),
        }
    }

    /// What the reading says about whether the tree is empty: a process that is held is running
    /// whatever else could not be read; nothing held and something unread, or no reading, says
    /// nothing.
    fn emptiness(&self) -> Emptiness {
        match self {
            Self::Seen { held, .. } if !held.is_empty() => Emptiness::Nonempty,
            Self::Seen {
                unreadable: false, ..
            } => Emptiness::Empty,
            Self::Seen { .. } | Self::Failed => Emptiness::Unknown,
        }
    }
}

/// Reads `tree` again and again until a reading shows it empty or `until` has passed, and returns
/// the last reading. A reading is taken at the end whatever the earlier ones showed.
#[cfg(any(windows, test))]
async fn read_until_empty(
    tree: &impl Tree,
    mut seen: Reading,
    until: tokio::time::Instant,
) -> Reading {
    while !seen.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= until {
            break;
        }
        tokio::time::sleep((until - now).min(TREE_REREAD)).await;
        seen = Reading::of(tree).await;
    }
    seen
}

/// Ends the server's tree and says how it came out.
///
/// **The order.** The server's own state is read, and its input is closed unless it is gone. The
/// tree is read, and waited for until `begun` plus [`GRACE_WINDOW`] to be empty (not only for the
/// server to be gone: a command that is ending after the input closed is not forced early, and a
/// reading that fails does not end the wait). Nothing is forced before then. A tree that is still
/// not empty is terminated, and the processes the last reading before that showed are noted as
/// forced, or as not ended when the terminate is refused. Then the tree is read until it is empty
/// or [`FORCE_WAIT`] has passed, and the last reading is the emptiness: an empty one is
/// [`Emptiness::Empty`] and a later empty one settles an earlier failed one; a held process is
/// [`Emptiness::Nonempty`] and is named; a reading that failed, or that lists a process it could
/// not ask about and holds none it could, is [`Emptiness::Unknown`].
///
/// The clock is the caller's `begun`, which a session that is closing takes from the moment its own
/// stop began, so that its forcing and this ending keep one clock.
#[cfg(any(windows, test))]
pub(crate) async fn end_tree(
    tree: &impl Tree,
    owned: &dyn Owned,
    begun: tokio::time::Instant,
) -> Retirement {
    let running = tree.root_running().await;
    if running {
        tree.close_input();
    }
    let seen = read_until_empty(tree, Reading::of(tree).await, begun + GRACE_WINDOW).await;
    if seen.is_empty() {
        return Retirement {
            ended: if running {
                Ended::Input
            } else {
                Ended::Already
            },
            forced: Vec::new(),
            survivors: Vec::new(),
            emptiness: Emptiness::Empty,
        };
    }
    // The server is read again as the tree is ended: it can have ended of itself since.
    let running_at_the_end = tree.root_running().await;
    let present = seen.held();
    let mut forced = Vec::new();
    match tree.terminate().await {
        Ok(()) => {
            for process in present {
                owned.forced(&process);
                forced.push(process);
            }
        }
        Err(why) => {
            for process in &present {
                owned.unsignalled(process, &why);
            }
        }
    }
    let settled = read_until_empty(
        tree,
        Reading::of(tree).await,
        tokio::time::Instant::now() + FORCE_WAIT,
    )
    .await;
    let ended = if !running {
        Ended::Already
    } else if !running_at_the_end {
        Ended::Input
    } else if tree.root_running().await {
        Ended::Alive
    } else {
        Ended::Force
    };
    let emptiness = settled.emptiness();
    Retirement {
        ended,
        forced,
        survivors: if emptiness == Emptiness::Nonempty {
            settled.held()
        } else {
            Vec::new()
        },
        emptiness,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use kr_protocol::identity::ProcessStartSource;
    use tokio::time::Instant;

    use super::*;

    fn process(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::WindowsProcessCreationTime, 1)
    }

    /// What the ending noted about the processes, as a session's record would.
    #[derive(Default)]
    struct Notes {
        forced: Mutex<Vec<ProcessStartIdentity>>,
        unsignalled: Mutex<Vec<(ProcessStartIdentity, String)>>,
    }

    impl Owned for Notes {
        fn below(&self, _server: &ProcessStartIdentity) -> Vec<ProcessStartIdentity> {
            Vec::new()
        }

        fn left(&self, _process: &ProcessStartIdentity) -> bool {
            false
        }

        fn forced(&self, process: &ProcessStartIdentity) {
            self.forced.lock().expect("the list").push(process.clone());
        }

        fn unsignalled(&self, process: &ProcessStartIdentity, why: &str) {
            self.unsignalled
                .lock()
                .expect("the list")
                .push((process.clone(), why.to_owned()));
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        RootRunning,
        CloseInput,
        Members,
        Terminate,
    }

    /// A tree whose readings a case writes down. Nothing in it is a process: a terminate here is a
    /// note, so no case of the ladder's order signals anything.
    struct Fake {
        begun: Instant,
        calls: Mutex<Vec<(Call, Duration)>>,
        /// What the tree holds before it is terminated, by how long after the ending began.
        before: Box<dyn Fn(Duration) -> Result<Vec<Member>, String> + Send + Sync>,
        /// What it holds after, one reading each; the last is read again and again.
        after: Mutex<VecDeque<Result<Vec<Member>, String>>>,
        /// When the root ends of itself, or never.
        root_ends_at: Option<Duration>,
        /// Whether the terminate ends the root.
        terminate_ends_root: bool,
        terminate_answer: Result<(), String>,
        terminated: Mutex<bool>,
    }

    impl Fake {
        fn new(
            begun: Instant,
            before: impl Fn(Duration) -> Result<Vec<Member>, String> + Send + Sync + 'static,
        ) -> Self {
            Self {
                begun,
                calls: Mutex::new(Vec::new()),
                before: Box::new(before),
                after: Mutex::new(VecDeque::from([Ok(Vec::new())])),
                root_ends_at: None,
                terminate_ends_root: true,
                terminate_answer: Ok(()),
                terminated: Mutex::new(false),
            }
        }

        fn after(self, readings: Vec<Result<Vec<Member>, String>>) -> Self {
            *self.after.lock().expect("the readings") = readings.into();
            self
        }

        fn note(&self, call: Call) {
            self.calls
                .lock()
                .expect("the calls")
                .push((call, self.begun.elapsed()));
        }

        fn calls(&self) -> Vec<(Call, Duration)> {
            self.calls.lock().expect("the calls").clone()
        }

        fn when(&self, wanted: Call) -> Vec<Duration> {
            self.calls()
                .into_iter()
                .filter(|(call, _)| *call == wanted)
                .map(|(_, at)| at)
                .collect()
        }

        fn terminated(&self) -> bool {
            *self.terminated.lock().expect("the flag")
        }
    }

    impl Tree for Fake {
        async fn root_running(&self) -> bool {
            self.note(Call::RootRunning);
            if self.terminated() && self.terminate_ends_root {
                return false;
            }
            self.root_ends_at
                .is_none_or(|ends| self.begun.elapsed() < ends)
        }

        fn close_input(&self) {
            self.note(Call::CloseInput);
        }

        async fn members(&self) -> Result<Vec<Member>, String> {
            self.note(Call::Members);
            if !self.terminated() {
                return (self.before)(self.begun.elapsed());
            }
            let mut after = self.after.lock().expect("the readings");
            if after.len() > 1 {
                after.pop_front().expect("a reading")
            } else {
                after.front().cloned().expect("a reading")
            }
        }

        async fn terminate(&self) -> Result<(), String> {
            self.note(Call::Terminate);
            *self.terminated.lock().expect("the flag") = true;
            self.terminate_answer.clone()
        }
    }

    fn held(pids: &[u64]) -> Vec<Member> {
        pids.iter().map(|pid| Member::Held(process(*pid))).collect()
    }

    const ROOT: u64 = 10;
    const COMMAND: u64 = 11;

    /// A tree that holds the server and its command until it is terminated.
    fn stubborn(begun: Instant) -> Fake {
        Fake::new(begun, |_| Ok(held(&[ROOT, COMMAND])))
    }

    async fn ending(tree: &Fake, notes: &Notes, begun: Instant) -> Retirement {
        end_tree(tree, notes, begun).await
    }

    /// The Unix reading is by parentage: what it found running is the answer, and it never says it
    /// could not tell.
    #[test]
    fn kr_req_07_60_a_reading_by_parentage_is_empty_or_nonempty_and_never_unknown() {
        assert_eq!(Emptiness::of_survivors(&[]), Emptiness::Empty);
        assert_eq!(Emptiness::of_survivors(&[process(1)]), Emptiness::Nonempty);
        assert_eq!(
            Emptiness::of_survivors(&[process(1), process(2)]),
            Emptiness::Nonempty
        );
    }

    /// A server that is gone before the ending begins and holds nothing is `Already`: its input is
    /// not closed and nothing is ended.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_a_server_gone_before_the_ending_began_is_already_and_nothing_is_ended() {
        let begun = Instant::now();
        let mut tree = Fake::new(begun, |_| Ok(Vec::new()));
        tree.root_ends_at = Some(Duration::ZERO);
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert_eq!(retirement.ended, Ended::Already);
        assert_eq!(retirement.emptiness, Emptiness::Empty);
        assert!(retirement.forced.is_empty() && retirement.survivors.is_empty());
        assert!(tree.when(Call::CloseInput).is_empty());
        assert!(tree.when(Call::Terminate).is_empty());
    }

    /// The order of the ending: the server's state is read, its input closed, the tree read and waited
    /// for until the window is over, and only then terminated and read again.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_53_a_tree_that_will_not_empty_is_terminated_when_the_window_is_over() {
        let begun = Instant::now();
        let tree = stubborn(begun);
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        let calls = tree.calls();
        let place = |wanted: Call| {
            calls
                .iter()
                .position(|(call, _)| *call == wanted)
                .expect("the call was made")
        };
        assert_eq!(calls[0].0, Call::RootRunning);
        assert!(place(Call::RootRunning) < place(Call::CloseInput));
        assert!(place(Call::CloseInput) < place(Call::Members));
        assert!(place(Call::Members) < place(Call::Terminate));
        // Nothing is forced before the window is over, and what is read after is read after.
        let terminated = tree.when(Call::Terminate);
        assert_eq!(terminated.len(), 1);
        assert!(terminated[0] >= GRACE_WINDOW, "{:?}", terminated[0]);
        assert!(
            terminated[0] < GRACE_WINDOW + Duration::from_millis(100),
            "{:?}",
            terminated[0]
        );
        let read = tree.when(Call::Members);
        assert!(read.iter().filter(|at| **at < terminated[0]).count() > 1);
        assert!(read.iter().any(|at| *at >= terminated[0]));

        assert_eq!(retirement.ended, Ended::Force);
        assert_eq!(retirement.emptiness, Emptiness::Empty);
        assert_eq!(retirement.forced, vec![process(ROOT), process(COMMAND)]);
        assert_eq!(*notes.forced.lock().expect("the list"), retirement.forced);
        assert!(retirement.survivors.is_empty());
    }

    /// A tree that empties of itself inside the window is not terminated, and the ending does not
    /// wait for the window.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_53_a_tree_that_empties_inside_the_window_is_never_terminated() {
        let begun = Instant::now();
        let mut tree = Fake::new(begun, |at| {
            if at < Duration::from_secs(1) {
                Ok(held(&[ROOT, COMMAND]))
            } else {
                Ok(Vec::new())
            }
        });
        tree.root_ends_at = Some(Duration::from_secs(1));
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert_eq!(retirement.ended, Ended::Input);
        assert_eq!(retirement.emptiness, Emptiness::Empty);
        assert!(retirement.forced.is_empty());
        assert!(tree.when(Call::Terminate).is_empty());
        assert!(begun.elapsed() < GRACE_WINDOW, "{:?}", begun.elapsed());
    }

    /// A command left behind by a server that ended is waited for until the window is over, then
    /// ended with the terminate, and only it is noted as forced.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_53_a_command_left_by_a_server_that_ended_is_forced_when_the_window_is_over()
    {
        let begun = Instant::now();
        let mut tree = Fake::new(begun, |at| {
            if at < Duration::from_millis(100) {
                Ok(held(&[ROOT, COMMAND]))
            } else {
                Ok(held(&[COMMAND]))
            }
        });
        tree.root_ends_at = Some(Duration::from_millis(100));
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert!(tree.when(Call::Terminate)[0] >= GRACE_WINDOW);
        assert_eq!(retirement.ended, Ended::Input);
        assert_eq!(retirement.forced, vec![process(COMMAND)]);
        assert_eq!(retirement.emptiness, Emptiness::Empty);
    }

    /// A process that is in the tree after the terminate and the wait is named, and the hold stays.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_a_survivor_after_the_terminate_is_nonempty_and_named() {
        let begun = Instant::now();
        let tree = stubborn(begun).after(vec![Ok(held(&[COMMAND, 12]))]);
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert_eq!(retirement.emptiness, Emptiness::Nonempty);
        assert_eq!(retirement.survivors, vec![process(COMMAND), process(12)]);
        // The reading went on for as long as a forced process is given to be gone, and no longer.
        let ended_at = begun.elapsed();
        assert!(ended_at >= GRACE_WINDOW + FORCE_WAIT, "{ended_at:?}");
        assert!(
            ended_at < GRACE_WINDOW + FORCE_WAIT + Duration::from_millis(100),
            "{ended_at:?}"
        );
    }

    /// A tree that cannot be read is not said to be empty.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_a_failed_enumeration_is_unknown() {
        let begun = Instant::now();
        let tree = stubborn(begun).after(vec![Err("the job would not say".to_owned())]);
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert_eq!(retirement.emptiness, Emptiness::Unknown);
        assert!(retirement.survivors.is_empty());
    }

    /// An enumeration that failed becomes empty only by a later one that succeeds and is empty.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_an_unknown_becomes_empty_only_by_a_later_empty_reading() {
        let begun = Instant::now();
        let tree = stubborn(begun).after(vec![
            Err("the job would not say".to_owned()),
            Err("the job would not say".to_owned()),
            Ok(Vec::new()),
        ]);
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert_eq!(retirement.emptiness, Emptiness::Empty);
        assert!(
            begun.elapsed() < GRACE_WINDOW + FORCE_WAIT,
            "the reading stopped at the empty one: {:?}",
            begun.elapsed()
        );
    }

    /// A member that cannot be asked about leaves it unknown; one that is held beside it is
    /// running, so it is not.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_a_member_that_cannot_be_read_is_unknown_unless_one_beside_it_is_held() {
        let begun = Instant::now();
        let unreadable = Member::Unreadable("pid 12 could not be opened".to_owned());
        let alone = stubborn(begun).after(vec![Ok(vec![unreadable.clone()])]);
        let retirement = ending(&alone, &Notes::default(), begun).await;
        assert_eq!(retirement.emptiness, Emptiness::Unknown);

        let begun = Instant::now();
        let beside = stubborn(begun).after(vec![Ok(vec![unreadable, Member::Held(process(13))])]);
        let retirement = ending(&beside, &Notes::default(), begun).await;
        assert_eq!(retirement.emptiness, Emptiness::Nonempty);
        assert_eq!(retirement.survivors, vec![process(13)]);
    }

    /// A reading that fails while the window runs does not end the wait early and is not a
    /// reason to terminate before the window is over.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_53_a_failed_reading_inside_the_window_does_not_end_the_wait() {
        let begun = Instant::now();
        let tree = Fake::new(begun, |_| Err("the job would not say".to_owned()));
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert!(tree.when(Call::Terminate)[0] >= GRACE_WINDOW);
        // Nothing was read, so nothing is named as forced.
        assert!(retirement.forced.is_empty());
        assert_eq!(retirement.emptiness, Emptiness::Empty);
    }

    /// A terminate that is refused forces nothing, says why for each process it did not end, and
    /// leaves the tree as it was.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_a_refused_terminate_forces_nothing_and_is_noted_for_each_member() {
        let begun = Instant::now();
        let mut tree = stubborn(begun).after(vec![Ok(held(&[ROOT, COMMAND]))]);
        tree.terminate_answer = Err("access was denied".to_owned());
        tree.terminate_ends_root = false;
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert!(retirement.forced.is_empty());
        assert!(notes.forced.lock().expect("the list").is_empty());
        let unsignalled = notes.unsignalled.lock().expect("the list").clone();
        assert_eq!(
            unsignalled,
            vec![
                (process(ROOT), "access was denied".to_owned()),
                (process(COMMAND), "access was denied".to_owned()),
            ]
        );
        assert_eq!(retirement.ended, Ended::Alive);
        assert_eq!(retirement.emptiness, Emptiness::Nonempty);
    }

    /// A server that is still running when the wait for it is over is alive, and is among the
    /// survivors.
    #[tokio::test(start_paused = true)]
    async fn kr_req_07_60_a_server_that_outlives_the_terminate_is_alive_and_a_survivor() {
        let begun = Instant::now();
        let mut tree = stubborn(begun).after(vec![Ok(held(&[ROOT]))]);
        tree.terminate_ends_root = false;
        let notes = Notes::default();

        let retirement = ending(&tree, &notes, begun).await;
        assert_eq!(retirement.ended, Ended::Alive);
        assert_eq!(retirement.survivors, vec![process(ROOT)]);
        assert_eq!(retirement.emptiness, Emptiness::Nonempty);
    }

    /// The server's input is one pipe for every holder: a write that waits on a server that reads
    /// nothing fails when another holder closes it.
    #[tokio::test]
    async fn kr_req_07_60_a_write_that_waits_on_the_input_ends_when_another_holder_closes_it() {
        use tokio::io::AsyncWriteExt as _;

        // A pipe that holds eight bytes and has no reader.
        let (written, _unread) = tokio::io::duplex(8);
        let input = Input::new(Some(written));
        let mut writer = input.clone();
        let mut closer = input;
        let waiting = tokio::spawn(async move { writer.write_all(&[b'x'; 1 << 16]).await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "the write waits on a full pipe");
        closer.shutdown().await.expect("the input closes");
        let ended = tokio::time::timeout(Duration::from_secs(30), waiting)
            .await
            .expect("the waiting write was woken")
            .expect("the task ends");
        assert!(ended.is_err(), "the write failed as the input was closed");
    }
}
