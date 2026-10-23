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
//!   request that a connector's table answered and a binding interpreted, and has not settled it.
//!   A question is open when the question ledger holds one that has not been answered, cancelled or
//!   expired. A turn is running when an instance's connector table named a turn start and no turn
//!   end has followed. [`follow_evidence`] reads these when something that can change them
//!   wakes it, never at a look at the terminal, and re-reads while a question is open because a
//!   question can run out of time with nothing to wake it.
//! * **The holder of the terminal**, which the adoption watch reads on its own pace. [`Following`]
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

/// The longest name a program is given, in bytes.
#[cfg(unix)]
const NAME_BYTES: usize = 64;

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
pub struct Producer {
    runtime: Weak<SessionRuntime>,
    held: Mutex<Held>,
    /// Taken for the whole of a publication, so two facts arriving together are published in the
    /// order they were joined in and the last one wins.
    publishing: Mutex<()>,
    published: tokio::sync::watch::Sender<Application>,
}

/// The two kinds of fact the producer joins.
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
    #[must_use]
    pub fn new(runtime: Weak<SessionRuntime>) -> Arc<Self> {
        // What a live session starts as, which is what launching it made it: the shell, at its
        // prompt.
        let (published, _) =
            tokio::sync::watch::channel(describe(Evidence::default(), &Holder::Unread));
        Arc::new(Self {
            runtime,
            held: Mutex::new(Held::default()),
            publishing: Mutex::new(()),
            published,
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

    /// Takes the evidence the worker holds now.
    pub fn observe_evidence(&self, evidence: Evidence) {
        {
            let mut held = self
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if held.evidence == evidence {
                return;
            }
            held.evidence = evidence;
        }
        self.publish();
    }

    /// Takes what holds the terminal now.
    pub fn observe_holder(&self, holder: Holder) {
        {
            let mut held = self
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if held.holder == holder {
                return;
            }
            held.holder = holder;
        }
        self.publish();
    }

    /// Whether the session this describes has finished or gone.
    fn over(&self) -> bool {
        self.runtime
            .upgrade()
            .is_none_or(|runtime| !runtime.session().state().is_running())
    }

    /// Publishes what the held facts come to, if that is not what was published.
    ///
    /// The session takes it first, under its own lock and last of every lock this takes, and a
    /// receiver is told after; so a receiver that sees a change finds it in the summary.
    fn publish(&self) {
        let _publishing = self
            .publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        {
            let mut session = runtime.session();
            if !session.state().accepts_input() {
                // A session that is not live has nothing to describe, and closing cleared what it
                // had. What was held waits for a session that is.
                return;
            }
            session.set_application_state(application.state);
            session.set_application(application.name.clone());
        }
        self.published.send_replace(application);
    }
}

/// Reads the evidence each time something that can change it wakes the producer, until the session
/// is closed.
///
/// What it reads is the broker's two facts and whether the question ledger holds an open question.
/// Each wake is subscribed to before the read, so a change that lands during the read is not lost.
/// The reads happen here and never at a look at the terminal, which is what keeps an idle session
/// at one read of its foreground group for each look.
pub async fn follow_evidence(
    producer: Arc<Producer>,
    runtime: Arc<SessionRuntime>,
    broker: Arc<Broker>,
    questions: Arc<Questions>,
    journal_changes: Option<Arc<tokio::sync::Notify>>,
    now: impl Fn() -> Now,
) {
    let closed = runtime.wait_closed();
    tokio::pin!(closed);
    let changes = broker.application_changes();
    loop {
        let moved_questions = questions.subscribe();
        let moved_journal = journal_changes.as_ref().map(|journal| journal.notified());
        let moved_broker = changes.notified();
        let facts = broker.application();
        // A ledger that cannot be read says nothing, so it is taken for no question: a session is
        // not kept awake by a record that cannot be read.
        let question_open = questions.any_open(now()).unwrap_or(false);
        producer.observe_evidence(Evidence {
            approval_pending: facts.approval_pending,
            question_open,
            turn_running: facts.turn_running,
        });
        if producer.over() {
            return;
        }
        tokio::select! {
            () = moved_questions => {}
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
            _ = &mut closed => return,
        }
    }
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
    /// answered for. What a process runs cannot change without it starting an image again, so one
    /// reading serves every look until the leader, the image or the command is another.
    ran: Option<(Ran, bool)>,
}

/// What a reading of whether a leader runs a command was made of.
#[cfg(unix)]
#[derive(PartialEq, Eq)]
struct Ran {
    leader: u32,
    image: String,
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
            command: typed.clone(),
        };
        let runs_it = match ran {
            Some((read, held)) if *read == reading => *held,
            _ => {
                let held = runs(typed, &image, leader);
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
fn runs(typed: &str, image: &str, leader: u32) -> bool {
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
    let Some(arguments) = crate::broker::adoption::arguments_of(leader) else {
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
        if running.is_none() || canonical(interpreter) != running {
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
