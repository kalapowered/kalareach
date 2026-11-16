//! What a session's application is doing, as far as this worker can establish it.
//!
//! A session's application is whatever holds its terminal: the root shell at its prompt, or a
//! program the shell started. The worker is the only process that can tell, and what it says
//! reaches the person in two places: the session's application state (`shell_ready`,
//! `agent_busy`, `awaiting_input`, `awaiting_approval`), and the sleep demand of section 3, which
//! counts a working agent and a request waiting for a decision as work that justifies keeping the
//! machine awake.
//!
//! The producer holds two kinds of fact and joins them without reading anything:
//!
//! * **Evidence**, which the worker already keeps. An approval is pending when the broker holds a
//!   request that a connector's table answered and a binding interpreted, which nothing has
//!   settled and whose deadline, where the upstream put one on it, has not passed (an answer
//!   already in flight is pending whatever the deadline says). A question is open when the
//!   question ledger holds one that has not been answered, cancelled or expired. A turn is running
//!   when an instance's connector table named a turn start and no turn end has followed.
//!   [`follow_evidence`] reads these when something that can change them wakes it, never at a look
//!   at the terminal, and re-reads while a question is open because a question can run out of time
//!   with nothing to wake it, and at the next deadline of a waiting approval, or in fifteen
//!   seconds if that comes first, for the same reason.
//! * **The holder of the terminal**, which the adoption watch reads on its own pace. `Following`
//!   turns each of its looks into a [`Holder`]: the root shell, or a program with the name a person
//!   knows it by. A program is published once two looks in a row have seen the same group, so the
//!   shell's own image between a fork and an exec, and a command shorter than a look, never are.
//!
//! The state is the first of these that holds: an approval waiting, a question open, a turn
//! running, a program with nothing known about it (none), the shell at its prompt. Where the
//! worker reads no foreground (Windows), the holder stays [`Holder::Unread`], which counts as the
//! shell, as it did before this producer existed. A program that has no turn routes in its
//! connector table, such as one whose hooks give no turn boundary, is never reported as busy: the
//! worker does not know that it is.
//!
//! What a program is called is the file name of what the shell integration answered for the line,
//! when it answered exactly one and that is what the group's leader is running (the image itself,
//! or the script an interpreter was given), and otherwise of the executable the leader runs. A
//! program run through an interpreter with no script to name is named by the interpreter.

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kr_protocol::session::ApplicationState;

use crate::broker::Broker;
use crate::questions::{Now, Questions};
use crate::runtime::SessionRuntime;

/// How often the ledger is read again while a question is open.
///
/// A question runs out of time with nothing to say so, and the producer reads the ledger when
/// something wakes it. While one is open the read is repeated at this pace, which is the pace the
/// sleep demand looks at the session on, so an expired question stops counting as soon as the
/// demand would have noticed. A session with no question open is never read on a timer.
pub const QUESTION_RECHECK: Duration = Duration::from_secs(15);

/// The longest a wait for an approval's deadline goes before the clock is read again.
///
/// A deadline is a time on the wall clock and the wait is on a clock that stops while the machine
/// sleeps and knows nothing of a wall clock that is stepped, so a long wait is looked at again at
/// this pace.
pub const DEADLINE_RECHECK: Duration = Duration::from_secs(15);

/// The longest name a program is given, in bytes.
#[cfg(unix)]
const NAME_BYTES: usize = 64;

/// The wall clock the producer measures an approval's deadline against.
///
/// In this host's own tests a test can move it forward, which is how a case reaches a deadline
/// without waiting for the real time to pass it.
#[derive(Clone, Debug, Default)]
pub struct DeadlineClock {
    #[cfg(feature = "testing")]
    moved_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl DeadlineClock {
    /// The time now, in UTC milliseconds.
    #[must_use]
    pub fn now(&self) -> kr_protocol::scalars::TimestampMs {
        let now = kr_ipc::now_ms();
        #[cfg(feature = "testing")]
        let now = kr_protocol::scalars::TimestampMs::new(
            now.get()
                .saturating_add(self.moved_ms.load(std::sync::atomic::Ordering::Acquire)),
        );
        now
    }

    /// Moves the clock forward by `by`.
    #[cfg(feature = "testing")]
    pub fn move_forward(&self, by: Duration) {
        self.moved_ms.fetch_add(
            u64::try_from(by.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::AcqRel,
        );
    }
}

/// What the worker holds that says what the application is doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    /// The broker holds an approval nothing has settled.
    pub approval_pending: bool,
    /// The question ledger holds a question that is open.
    pub question_open: bool,
    /// An instance is running a turn.
    pub turn_running: bool,
}

/// What holds the session's terminal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Holder {
    /// The terminal's foreground is not read here, so the shell is taken to hold it.
    #[default]
    Unread,
    /// The root shell, at its prompt.
    Shell,
    /// A program the root shell started, with the name a person knows it by where one is known.
    Program(Option<String>),
}

/// What the session's application is, as the producer last published it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Application {
    /// The name of the program in the foreground; none when the shell holds the terminal.
    pub name: Option<String>,
    /// What it is doing, where that is known.
    pub state: Option<ApplicationState>,
}

/// Joins the evidence and the holder into what the application is.
#[must_use]
pub fn describe(evidence: Evidence, holder: &Holder) -> Application {
    let name = match holder {
        Holder::Program(name) => name.clone(),
        Holder::Unread | Holder::Shell => None,
    };
    let state = if evidence.approval_pending {
        Some(ApplicationState::AwaitingApproval)
    } else if evidence.question_open {
        Some(ApplicationState::AwaitingInput)
    } else if evidence.turn_running {
        Some(ApplicationState::AgentBusy)
    } else if matches!(holder, Holder::Program(_)) {
        None
    } else {
        Some(ApplicationState::ShellReady)
    };
    Application { name, state }
}

/// One session's application, and the one place it is published from.
///
/// The facts are written by the tasks that read them, and none of those tasks waits for the
/// session: a fact is written where a read of a held session finds it (in `record`), and a
/// publisher thread of the producer's own makes the publication, which takes the session and may
/// wait for as long as a storage call holds it.
pub struct Producer {
    runtime: Weak<SessionRuntime>,
    held: Mutex<Held>,
    published: tokio::sync::watch::Sender<Application>,
    /// Tells the publisher that a publication may be owed. It holds one wake, which stands for
    /// every fact that joined before the publisher reads them, so a fact that joins while the
    /// publisher waits for the session, or while it makes a publication, is read after it. Every
    /// change sends one, whatever has been published: what is published changes only when the
    /// publisher makes a publication, and a change back to a value already published can join
    /// while an older one is in flight.
    owed: std::sync::mpsc::SyncSender<Wake>,
    /// Stand after the publisher has taken the session, before it reads the facts, and before it
    /// sends what it has read, for this host's own tests.
    #[cfg(feature = "testing")]
    after_the_take: crate::testing::Stall,
    /// Stands in the question ledger's reader after it has read the ledger and before it records
    /// what it found, for this host's own tests.
    #[cfg(feature = "testing")]
    before_the_fact: crate::testing::Stall,
    /// How many rounds the evidence loop has begun and how many of them have come to a wait, for
    /// this host's own tests: the two are equal while the loop waits.
    #[cfg(feature = "testing")]
    rounds: std::sync::atomic::AtomicUsize,
    #[cfg(feature = "testing")]
    waits: std::sync::atomic::AtomicUsize,
    /// How many reads of the question ledger by the ledger's reader have failed, counted once the
    /// reader has dealt with the failure, for this host's own tests.
    #[cfg(feature = "testing")]
    ledger_failures: std::sync::atomic::AtomicUsize,
    #[cfg(feature = "testing")]
    before_the_send: crate::testing::Stall,
    /// How many helper threads of this producer are alive: its publisher, and the reader of the
    /// question ledger that the evidence loop starts.
    #[cfg(feature = "testing")]
    helpers: Arc<std::sync::atomic::AtomicUsize>,
}

/// One live helper thread of a producer, counted for as long as it stands, for this host's own
/// tests.
#[cfg(feature = "testing")]
struct Counted(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(feature = "testing")]
impl Counted {
    fn new(alive: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        alive.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(Arc::clone(alive))
    }
}

#[cfg(feature = "testing")]
impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// What the publisher is told.
enum Wake {
    /// A publication is owed.
    Owed,
    /// Every publication owed before this wake has been made, for this host's own tests.
    #[cfg(feature = "testing")]
    Settled(std::sync::mpsc::Sender<()>),
}

/// The facts the producer joins, each written by the task that reads it.
#[derive(Debug, Default)]
struct Held {
    evidence: Evidence,
    holder: Holder,
}

impl std::fmt::Debug for Producer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Producer").finish_non_exhaustive()
    }
}

impl Producer {
    /// Builds the producer of one session's application.
    ///
    /// It holds the session weakly: a session that has gone is a session with nothing to describe.
    /// Its publisher is a thread that holds nothing while it waits to be told, and ends with the
    /// producer.
    ///
    /// # Panics
    ///
    /// Panics when the publisher's thread cannot be started.
    #[must_use]
    pub fn new(runtime: Weak<SessionRuntime>) -> Arc<Self> {
        // What a live session starts as, which is what launching it made it: the shell, at its
        // prompt.
        let (published, _) =
            tokio::sync::watch::channel(describe(Evidence::default(), &Holder::Unread));
        let (owed, wakes) = std::sync::mpsc::sync_channel(1);
        #[cfg(feature = "testing")]
        let helpers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        #[cfg(feature = "testing")]
        let counted = Counted::new(&helpers);
        Arc::new_cyclic(|this: &Weak<Self>| {
            let producer = Weak::clone(this);
            std::thread::Builder::new()
                .name("kr-application-publisher".to_owned())
                .spawn(move || {
                    #[cfg(feature = "testing")]
                    let _counted = counted;
                    publish_when_owed(&producer, &wakes);
                })
                .expect("a thread for the application's publisher");
            Self {
                runtime,
                held: Mutex::new(Held::default()),
                published,
                owed,
                #[cfg(feature = "testing")]
                after_the_take: crate::testing::Stall::default(),
                #[cfg(feature = "testing")]
                before_the_fact: crate::testing::Stall::default(),
                #[cfg(feature = "testing")]
                rounds: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(feature = "testing")]
                waits: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(feature = "testing")]
                ledger_failures: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(feature = "testing")]
                before_the_send: crate::testing::Stall::default(),
                #[cfg(feature = "testing")]
                helpers,
            }
        })
    }

    /// Returns what the producer publishes, and wakes the receiver at each change.
    ///
    /// A change is visible in the session's summary before the receiver sees it.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Application> {
        self.published.subscribe()
    }

    /// Returns what the producer has published.
    #[must_use]
    pub fn application(&self) -> Application {
        self.published.borrow().clone()
    }

    /// Waits until every publication that was owed when it was called has been made, for this
    /// host's own tests. A publication waits for the session, so this waits for it too.
    ///
    /// # Panics
    ///
    /// Panics when the publisher has gone, which it does only with the producer.
    #[cfg(feature = "testing")]
    pub fn settle(&self) {
        let (done, settled) = std::sync::mpsc::channel();
        self.owed
            .send(Wake::Settled(done))
            .expect("the publisher is there while the producer is");
        settled
            .recv()
            .expect("the publisher answers while the producer is there");
    }

    /// Returns how many helper threads of this producer are alive, for this host's own tests: its
    /// publisher, and the reader of the question ledger while the evidence loop runs. The count is
    /// shared, so it can be read after the producer has gone.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn helpers_alive(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.helpers)
    }

    /// Takes what the broker holds now: whether a request waits for a decision and whether an
    /// instance runs a turn.
    pub fn observe_broker(&self, approval_pending: bool, turn_running: bool) {
        self.join(|held| {
            let changed = held.evidence.approval_pending != approval_pending
                || held.evidence.turn_running != turn_running;
            held.evidence.approval_pending = approval_pending;
            held.evidence.turn_running = turn_running;
            changed
        });
    }

    /// Takes whether the question ledger holds an open question, and says whether that is a change.
    fn observe_questions(&self, question_open: bool) -> bool {
        self.join(|held| {
            let changed = held.evidence.question_open != question_open;
            held.evidence.question_open = question_open;
            changed
        })
    }

    /// Takes what holds the terminal now.
    pub fn observe_holder(&self, holder: Holder) {
        self.join(|held| {
            let changed = held.holder != holder;
            held.holder = holder;
            changed
        });
    }

    /// Whether the last read of the question ledger found a question open.
    fn question_open(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .evidence
            .question_open
    }

    /// Joins one fact to the others and records what they come to, and says whether the fact
    /// changed anything. Nothing here waits for the session.
    fn join(&self, fact: impl FnOnce(&mut Held) -> bool) -> bool {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = fact(&mut held);
        if changed {
            self.record(&held);
        }
        changed
    }

    /// Writes what the facts held come to into the session's input domain, where a read of a
    /// session that something holds finds it, and tells the publisher.
    ///
    /// It is made as the fact joins the others, with the facts locked, so the writes go in the
    /// order the facts were joined in, and it waits for nothing. A turn that begins while a storage
    /// call holds the session is therefore in the answer of a read that cannot take the session,
    /// whatever the task that read it was doing before. A question cannot begin then: it is created
    /// with the session taken. The domain's lock is taken last, for the write alone.
    fn record(&self, held: &Held) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let application = describe(held.evidence, &held.holder);
        runtime
            .input()
            .lock()
            .set_application_state(application.state);
        // A full channel holds a wake already, and the publisher reads the facts after it. The
        // publisher publishes only what differs from what is published, so a wake that finds
        // nothing owed costs one read of the facts.
        let _ = self.owed.try_send(Wake::Owed);
    }

    /// Publishes what the held facts come to, if that is not what was published.
    ///
    /// Only the publisher calls it. The session takes it first, and the facts are read under the
    /// session, so what is published is the latest the facts say and not what they said when the
    /// publisher was told. The name goes into the session before a receiver is told, so a receiver
    /// that sees a change finds it in the summary.
    fn publish(&self) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let application = {
            let mut session = runtime.session();
            #[cfg(feature = "testing")]
            self.after_the_take.stand();
            if !session.state().accepts_input() {
                // A session that is not live has nothing to describe, and closing cleared what it
                // had. What was held waits for a session that is.
                return;
            }
            let application = {
                let held = self
                    .held
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                describe(held.evidence, &held.holder)
            };
            if *self.published.borrow() == application {
                return;
            }
            session.set_application(application.name.clone());
            application
        };
        #[cfg(feature = "testing")]
        self.before_the_send.stand();
        self.published.send_replace(application);
    }

    /// Stops the question ledger's reader after it has read the ledger and before it records what
    /// it found, for this host's own tests. Returns the end that says the reader has arrived there
    /// and the end that lets it go on; the stop fires once.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn pause_ledger_reader_before_its_fact(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.before_the_fact.arm_blocking()
    }

    /// Returns how many rounds the evidence loop has begun and how many of them have come to a wait
    /// on its stream, for this host's own tests. While the two are equal the loop waits, with the
    /// facts it last read.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn loop_rounds(&self) -> (usize, usize) {
        (
            self.rounds.load(std::sync::atomic::Ordering::SeqCst),
            self.waits.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// Returns how many reads of the question ledger by the ledger's reader have failed, for this
    /// host's own tests. A read is counted after the reader has dealt with its failure, so whatever
    /// the reader records for a failed read is recorded when the count has risen.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn failed_ledger_reads(&self) -> usize {
        self.ledger_failures
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stops the next publication after the publisher has taken the session and before it reads the
    /// facts, for this host's own tests. Returns the end that says the publisher has arrived there
    /// and the end that lets it go on; the stop fires once. Facts that join while it stands there
    /// are the ones the publication must carry.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn pause_after_the_take(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.after_the_take.arm_blocking()
    }

    /// Stops the next publication after the publisher has read the facts and written the name, and
    /// before it tells a receiver, for this host's own tests. Returns the end that says the
    /// publisher has arrived there and the end that lets it go on; the stop fires once.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn pause_before_the_send(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.before_the_send.arm_blocking()
    }
}

/// The publisher: waits to be told that a publication is owed, and makes it. It holds nothing
/// while it waits, and it ends when the producer has gone.
fn publish_when_owed(producer: &Weak<Producer>, wakes: &std::sync::mpsc::Receiver<Wake>) {
    while let Ok(wake) = wakes.recv() {
        match wake {
            Wake::Owed => {
                let Some(producer) = producer.upgrade() else {
                    return;
                };
                producer.publish();
            }
            #[cfg(feature = "testing")]
            Wake::Settled(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// Reads the evidence each time something that can change it wakes the producer, until the session
/// is closed.
///
/// What it reads is the broker's two facts, and it asks for a read of the question ledger. Each
/// wake is subscribed to before the read, so a change that lands during the read is not lost. The
/// reads happen here and never at a look at the terminal, which is what keeps an idle session at
/// one read of its foreground group for each look.
///
/// Between two reads of its stream the loop takes nothing that a held session blocks: not the
/// session, which it never takes, and not the question ledger's lock, which a question's commit
/// holds with the session taken. The ledger is read by a thread of its own, and the loop writes
/// each fact where a read of a held session finds it. What it still waits for is the broker's
/// lock, which a broker commit holds across its own write: behind a commit that waits for the
/// journal's file while a hold keeps it, for at most the store's five seconds, and behind a commit
/// to a disk that has stopped for as long as the disk does, as the loop did before.
pub async fn follow_evidence(
    producer: Arc<Producer>,
    runtime: Arc<SessionRuntime>,
    broker: Arc<Broker>,
    questions: Arc<Questions>,
    journal_changes: Option<Arc<tokio::sync::Notify>>,
    clock: Arc<dyn kr_ipc::clock::SharedClock>,
    deadlines: DeadlineClock,
) {
    let changes = broker.application_changes();
    let ledger_read = Arc::new(tokio::sync::Notify::new());
    let ask = read_the_ledger_apart(&producer, &questions, Arc::clone(&ledger_read), clock);
    loop {
        #[cfg(feature = "testing")]
        producer
            .rounds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let moved_questions = questions.subscribe();
        let moved_ledger = ledger_read.notified();
        let moved_journal = journal_changes.as_ref().map(|journal| journal.notified());
        let moved_broker = changes.notified();
        let moved_closed = runtime.closure_notified();
        let reading = deadlines.now();
        let facts = broker.application(reading);
        producer.observe_broker(facts.approval_pending, facts.turn_running);
        // A read that was asked for and not begun is enough for every ask after it.
        let _ = ask.try_send(());
        // The lifecycle is the input domain's, which nothing that holds the session holds too.
        if !runtime.input().lock().state().is_running() {
            return;
        }
        let question_open = producer.question_open();
        #[cfg(feature = "testing")]
        producer
            .waits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::select! {
            () = moved_questions => {}
            () = moved_ledger => {}
            () = async {
                match moved_journal {
                    Some(journal) => journal.await,
                    None => std::future::pending().await,
                }
            } => {}
            () = moved_broker => {}
            () = async {
                if question_open {
                    tokio::time::sleep(QUESTION_RECHECK).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            // An approval stops being answerable at the deadline the upstream put on it, and
            // nothing else says so: this is the read that lifts it. The timer counts the time
            // the machine is awake, which a suspended machine does not, and the deadline is a
            // wall clock time, so the wait is cut short to look again.
            () = async {
                match facts.next_deadline {
                    Some(deadline) => {
                        let left = deadline.get().saturating_sub(reading.get());
                        tokio::time::sleep(Duration::from_millis(left).min(DEADLINE_RECHECK))
                            .await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {}
            () = moved_closed => {}
        }
    }
}

/// Starts the thread that reads the question ledger for [`follow_evidence`], and returns the end
/// that asks it to read.
///
/// A read of the ledger takes its store's lock and calls the store. A question's creation, answer
/// or cancellation holds that lock across its own commit, with the session taken, so a loop that
/// read the ledger would stand still for as long as that storage call does, and read nothing of
/// the broker meanwhile. The thread reads when it is asked, writes what it found as the question
/// fact, and tells the loop only when the fact changed, which is when the loop arms its timer
/// anew. A ledger that cannot be read says nothing: the question fact keeps its last value, because
/// a question that is still open does not stop being open when its ledger fails to answer. The
/// thread ends when the loop does, because the asking end goes with it.
///
/// # Panics
///
/// Panics when the thread cannot be started.
fn read_the_ledger_apart(
    producer: &Arc<Producer>,
    questions: &Arc<Questions>,
    moved: Arc<tokio::sync::Notify>,
    clock: Arc<dyn kr_ipc::clock::SharedClock>,
) -> std::sync::mpsc::SyncSender<()> {
    let (ask, asked) = std::sync::mpsc::sync_channel(1);
    #[cfg(feature = "testing")]
    let counted = Counted::new(&producer.helpers);
    let (producer, questions) = (Arc::downgrade(producer), Arc::downgrade(questions));
    std::thread::Builder::new()
        .name("kr-question-ledger-reader".to_owned())
        .spawn(move || {
            #[cfg(feature = "testing")]
            let _counted = counted;
            while asked.recv().is_ok() {
                // Neither outlives its owner: a producer or a ledger that has gone ends the thread.
                let (Some(producer), Some(questions)) = (producer.upgrade(), questions.upgrade())
                else {
                    return;
                };
                let now = Now {
                    utc_ms: kr_ipc::now_ms(),
                    boot_ms: clock.boot_elapsed_ms(),
                };
                // A ledger that cannot be read says nothing, so the fact keeps its last value: an
                // error is not "no question".
                let read = questions.any_open(now);
                #[cfg(feature = "testing")]
                let failed = read.is_err();
                if let Ok(open) = read {
                    #[cfg(feature = "testing")]
                    producer.before_the_fact.stand();
                    if producer.observe_questions(open) {
                        moved.notify_waiters();
                    }
                }
                #[cfg(feature = "testing")]
                if failed {
                    producer
                        .ledger_failures
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        })
        .expect("a thread for the question ledger's reader");
    ask
}

/// Turns the adoption watch's looks at the terminal into what holds it.
///
/// A look that finds the root shell at its prompt is the shell, at once. A look that finds a
/// program is the program only when the look before it found the same process group, with the name
/// the later look read: a command that has only just been forked still runs the shell's image, and
/// a name that changed between two looks has not settled. A program that did not settle is not
/// published, and the shell stays the holder until one does.
#[cfg(unix)]
pub struct Following {
    producer: Arc<Producer>,
    /// The group and the name the previous look found, while a program held the terminal.
    previous: Option<(i32, Option<String>)>,
    /// Whether the leader of the group the previous look found runs the command the shell
    /// answered for. A process can replace what it runs without becoming another process or
    /// another image, as a script does when it execs its own interpreter on another script, so a
    /// reading serves the looks that find the same leader, image, arguments and command.
    ran: Option<(Ran, bool)>,
}

/// What a reading of whether a leader runs a command was made of.
#[cfg(unix)]
#[derive(PartialEq, Eq)]
struct Ran {
    leader: u32,
    image: String,
    /// The argument vector the leader runs with, which an exec of the same image changes.
    arguments: Option<Vec<String>>,
    command: String,
}

#[cfg(unix)]
impl Following {
    /// Follows what holds `producer`'s session's terminal.
    #[must_use]
    pub const fn new(producer: Arc<Producer>) -> Self {
        Self {
            producer,
            previous: None,
            ran: None,
        }
    }

    /// Takes one look: `None` when the root shell holds the terminal, and what the watch read when
    /// a program does.
    pub fn look(&mut self, foreground: Option<&crate::broker::adoption::Foreground>) {
        let Some(foreground) = foreground else {
            self.previous = None;
            self.producer.observe_holder(Holder::Shell);
            return;
        };
        let name = program_of(foreground, &mut self.ran);
        let settled = self
            .previous
            .as_ref()
            .is_some_and(|(group, earlier)| *group == foreground.group && *earlier == name);
        self.previous = Some((foreground.group, name.clone()));
        if settled {
            self.producer.observe_holder(Holder::Program(name));
        }
    }
}

/// Returns what a person knows the program in the foreground by.
///
/// The file name of what the shell integration answered for the line, when it answered for exactly
/// one command and that command is what the group's leader is running now, and otherwise of the
/// executable the leader runs. A line of several commands names none of them, and a command the
/// leader has replaced, as a wrapper does when it execs the program it starts, is not the program
/// that holds the terminal now. The leader is the process the group is named after, or, once it
/// has gone, the lowest-numbered member the root shell started.
#[cfg(unix)]
fn program_of(
    foreground: &crate::broker::adoption::Foreground,
    ran: &mut Option<(Ran, bool)>,
) -> Option<String> {
    let leader = leader_of(foreground)?;
    let image = crate::questions::binding::executable_of(leader)?;
    if let [(typed, _)] = foreground.answered.as_slice() {
        let reading = Ran {
            leader,
            image: image.clone(),
            arguments: crate::broker::adoption::arguments_of(leader),
            command: typed.clone(),
        };
        let runs_it = match ran {
            Some((read, held)) if *read == reading => *held,
            _ => {
                let held = runs(typed, &image, leader, reading.arguments.as_deref());
                *ran = Some((reading, held));
                held
            }
        };
        if runs_it && let Some(name) = name_of(typed) {
            return Some(name);
        }
    }
    name_of(&image)
}

/// Whether the command a person typed, as the shell integration resolved it, is what `leader` is
/// running: the image itself, or the script the interpreter named on the script's first line was
/// started with.
///
/// The second is shown only the way the system starts a script, and an argument that holds the
/// script's path is not enough: `tail -f script` reads a script and runs another program. The
/// leader's image is the interpreter the first line names (`env` and the program it looks up, for
/// a line that names `env`), and the script is the argument after the interpreter's own, resolved
/// where the leader works when it was given as a relative path.
#[cfg(unix)]
fn runs(typed: &str, image: &str, leader: u32, arguments: Option<&[String]>) -> bool {
    let canonical = |path: &std::path::Path| std::fs::canonicalize(path).ok();
    let Some(script) = canonical(std::path::Path::new(typed)) else {
        return false;
    };
    let running = canonical(std::path::Path::new(image));
    if running.as_ref() == Some(&script) {
        return true;
    }
    let Some(started_with) = first_line_of(&script) else {
        return false;
    };
    let Some(arguments) = arguments else {
        return false;
    };
    let words: Vec<&str> = started_with.split_whitespace().collect();
    let Some(interpreter) = words.first() else {
        return false;
    };
    let interpreter = std::path::Path::new(interpreter);
    let script_at = if interpreter.file_name().is_some_and(|name| name == "env") {
        // The program `env` looks up is the one that runs, started with the script alone.
        let [_, looked_up] = words.as_slice() else {
            return false;
        };
        let looked_up = std::path::Path::new(looked_up);
        let named = looked_up.file_name();
        if looked_up.components().count() != 1
            || named.is_none_or(|name| name.to_string_lossy().starts_with('-'))
            || running.as_ref().and_then(|image| image.file_name()) != named
        {
            return false;
        }
        1
    } else {
        // The system starts the interpreter with its own path as the first argument. The image
        // that runs is that file, or the program the system starts in its place: macOS's
        // `/bin/sh` starts the shell the machine selects, and keeps its own path as the first
        // argument. The first argument is the process's own claim, so it names a program for
        // display and never decides anything of authority.
        let image_is_it = same_file(interpreter, std::path::Path::new(image));
        let named_it = arguments.first().is_some_and(|first| {
            let first = std::path::Path::new(first);
            if first.is_absolute() {
                same_file(interpreter, first)
            } else {
                working_directory_of(leader)
                    .is_some_and(|directory| same_file(interpreter, &directory.join(first)))
            }
        });
        if !(image_is_it || named_it) {
            return false;
        }
        // Linux gives the interpreter the rest of the line as one argument; macOS gives it each
        // word.
        1 + if words.len() == 1 {
            0
        } else if cfg!(target_os = "linux") {
            1
        } else {
            words.len() - 1
        }
    };
    let Some(given) = arguments.get(script_at) else {
        return false;
    };
    let given = std::path::Path::new(given);
    let given = if given.is_absolute() {
        given.to_path_buf()
    } else {
        let Some(directory) = working_directory_of(leader) else {
            return false;
        };
        directory.join(given)
    };
    canonical(&given).is_some_and(|given| given == script)
}

/// Whether two paths name the same file, by the device and the file number each leads to.
#[cfg(unix)]
fn same_file(first: &std::path::Path, second: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    match (std::fs::metadata(first), std::fs::metadata(second)) {
        (Ok(first), Ok(second)) => first.dev() == second.dev() && first.ino() == second.ino(),
        _ => false,
    }
}

/// Returns the first line of a script after its `#!`, when it has one.
#[cfg(unix)]
fn first_line_of(script: &std::path::Path) -> Option<String> {
    use std::io::Read as _;

    let mut head = Vec::new();
    std::fs::File::open(script)
        .ok()?
        .take(512)
        .read_to_end(&mut head)
        .ok()?;
    let line = head.strip_prefix(b"#!")?;
    let line = line.split(|byte| *byte == b'\n').next()?;
    Some(String::from_utf8_lossy(line).trim().to_owned())
}

/// Returns the directory a process works in, as the kernel names it now.
#[cfg(target_os = "linux")]
fn working_directory_of(pid: u32) -> Option<std::path::PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// Returns the directory a process works in, as the kernel names it now.
#[cfg(target_os = "macos")]
fn working_directory_of(pid: u32) -> Option<std::path::PathBuf> {
    crate::broker::commands::working_directory_path_of(u64::from(pid))
}

/// No platform record of a process's working directory is read here, so a script given by a
/// relative path is not shown to be the one that runs.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const fn working_directory_of(_pid: u32) -> Option<std::path::PathBuf> {
    None
}

/// Returns the process the foreground group is named after, or the first of the root shell's
/// children left in it.
#[cfg(unix)]
fn leader_of(foreground: &crate::broker::adoption::Foreground) -> Option<u32> {
    let group = u32::try_from(foreground.group).ok()?;
    // The leader is the process the group is named after, and asking for it is a few reads; listing
    // the group is the way to find a stand-in once the leader has gone.
    if kr_ipc::identity::process_start_identity(group)
        .ok()
        .and_then(|process| crate::broker::adoption::group_of(&process))
        == Some(foreground.group)
    {
        return Some(group);
    }
    kr_ipc::identity::processes_in_group(group)
        .ok()?
        .into_iter()
        .filter(|pid| {
            kr_ipc::identity::process_start_identity(*pid)
                .ok()
                .and_then(|process| crate::questions::binding::parent_of(&process))
                .is_some_and(|parent| parent.matches(&foreground.root_shell))
        })
        .min()
}

/// Returns the name a path ends in, held to what a person is shown: no directory, no marker the
/// system appends to the image of a program whose file has gone, no control character, and at most
/// [`NAME_BYTES`] bytes.
#[cfg(unix)]
fn name_of(path: &str) -> Option<String> {
    let file = std::path::Path::new(path).file_name()?.to_string_lossy();
    let file = file.strip_suffix(" (deleted)").unwrap_or(&file);
    let mut name = String::new();
    for character in file.chars().filter(|character| !character.is_control()) {
        if name.len() + character.len_utf8() > NAME_BYTES {
            break;
        }
        name.push(character);
    }
    (!name.is_empty()).then_some(name)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A name is the file's own, held to what is shown.
    #[test]
    fn a_name_is_the_files_own_held_to_what_is_shown() {
        assert_eq!(name_of("/usr/local/bin/claude").as_deref(), Some("claude"));
        assert_eq!(name_of("vim").as_deref(), Some("vim"));
        assert_eq!(
            name_of("/tmp/tool (deleted)").as_deref(),
            Some("tool"),
            "the marker the system adds to the image of a removed file is not part of the name"
        );
        assert_eq!(
            name_of("/bin/we\u{1b}[31mird\n").as_deref(),
            Some("we[31mird"),
            "a control character never reaches a person"
        );
        let long = format!("/bin/{}", "é".repeat(100));
        let name = name_of(&long).expect("a name");
        assert!(name.len() <= NAME_BYTES && name.chars().all(|c| c == 'é'));
        assert_eq!(name_of("/"), None, "a path with no file name names nothing");
    }
}
