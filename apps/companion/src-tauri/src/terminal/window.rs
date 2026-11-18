//! Where a raw terminal view's window is, the moves the page makes, and the reports they owe.
//!
//! The page moves the window in view mode: sideways across a session wider than the view, up into
//! the session's history, and down the live screen. Each move is numbered by the page, in order.
//! The host is told the window's place in a viewport report, one at a time, and answers each with
//! the revision it left the window at; every screen it installs names the revision of the window
//! it is drawn for. That is what lets a report be settled by the screen it caused and by nothing
//! else: the answer and the screens reach the view from two writers, either can arrive first, and a
//! screen of an earlier revision, such as a repaint queued before the report, is not the report's.
//!
//! The page is never the one to decide where the window is. It draws the newest screen it was
//! sent, shifted by the moves it has not yet been told are settled, and it is told a move is settled
//! only together with a screen that holds it.

use std::collections::VecDeque;

use kr_client::projection::Screen;
use kr_protocol::attachment::ViewportPosition;
use kr_protocol::ids::RequestId;
use kr_protocol::scalars::U64;
use kr_protocol::session::Dimensions;

use super::anchor::{Anchor, AnchorPlace, Note};

/// How many times in a row a size the host did not take for now goes again with the host's next
/// word. After that it waits for the page to measure or move, so a host that keeps refusing is not
/// asked once for every word it says.
const RETRIES: u8 = 3;

/// One move the page made, numbered in the order it made them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    /// Move the window by `across` columns and `down` rows: to the right and down when positive.
    Pan {
        /// The page's number for this move.
        number: u64,
        /// Columns to the right.
        across: i64,
        /// Rows down.
        down: i64,
    },
    /// Bring a window in the session's history back to the live screen.
    Live {
        /// The page's number for this move.
        number: u64,
    },
}

impl Move {
    /// The page's number for the move.
    #[must_use]
    pub const fn number(self) -> u64 {
        match self {
            Self::Pan { number, .. } | Self::Live { number } => number,
        }
    }
}

/// Where a window starts, and its first column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    place: Place,
    column: u64,
}

/// Where a window's first row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place {
    /// On the live screen, at this line of it.
    Live(u64),
    /// In the history, at this row.
    History(u64),
}

impl Record {
    /// Where a window is when its attachment joins: at the live screen's first line and column, at
    /// revision 0, which is where the host puts it until a report moves it.
    const ORIGIN: Self = Self {
        place: Place::Live(0),
        column: 0,
    };

    /// Where the window of `screen` is.
    fn of(screen: &Screen) -> Self {
        let top = screen.viewport.top_row.get();
        let live_top = screen.viewport.screen_top_row.get();
        Self {
            place: if top < live_top {
                Place::History(top)
            } else {
                Place::Live(top - live_top)
            },
            column: screen.viewport.left_column.get(),
        }
    }

    /// Where a window restored to `anchor` is, when it lands on the anchor's own place and column.
    const fn from_anchor(anchor: &Anchor) -> Self {
        Self {
            place: match anchor.place() {
                AnchorPlace::History(row) => Place::History(row),
                AnchorPlace::Live(line) => Place::Live(line),
            },
            column: anchor.column(),
        }
    }

    /// The place a report names to leave the window where it is.
    const fn position(self) -> Option<ViewportPosition> {
        match self.place {
            Place::Live(0) => None,
            Place::Live(line) => Some(ViewportPosition::Line(U64::new(line))),
            Place::History(row) => Some(ViewportPosition::Row(U64::new(row))),
        }
    }
}

/// Moves not yet sent, gathered into what one report can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Run {
    /// Neighbouring moves that reverse on neither axis, and the number of the last of them.
    Pan { across: i64, down: i64, last: u64 },
    /// A return to the live screen. It joins nothing, so it is weighed only once every move before
    /// it has settled. A return that supersedes a restore names the place it goes to, which it
    /// reports whatever the record says: the host's window is not known to be where the record
    /// says while the restore is unsettled.
    Live {
        number: u64,
        absolute: Option<(Option<ViewportPosition>, u64)>,
    },
    /// A move that is not made, settled in its place in the order. It changed nothing.
    Skip { last: u64 },
}

/// One viewport report to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sending {
    /// The size the view is looking at.
    pub dimensions: Dimensions,
    /// Where the window's first row is to be: null for the live screen's first line.
    pub position: Option<ViewportPosition>,
    /// The window's first column.
    pub column: u64,
}

/// How the host answered one viewport report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Refused in the host's definite word: nothing changed, and the report is settled.
    Refused,
    /// Not settled: the host refused for now. A size is owed again, since a report states the size
    /// and place, and sending it again changes nothing a first one did not. A move is the person's
    /// gesture: it is settled as not taken.
    NotSettled,
    /// The host could not say what became of the report, or its answer could not be read. For a
    /// size or a move that is the same as a refusal for now. A restore stays in flight: it may have
    /// moved the window, and it is never sent again.
    Unknown,
    /// Accepted.
    Accepted {
        /// The revision the report left the window at.
        window_revision: u64,
    },
}

/// The one report in flight.
#[derive(Clone, Copy, Debug)]
struct InFlight {
    /// Its request, once it has been sent.
    request: Option<RequestId>,
    /// The revision its answer named, once it has one and until a screen naming it arrives.
    awaiting: Option<u64>,
    /// The number of the last move it carries, when it carries any. A report that carries none
    /// carries the size.
    carries: Option<u64>,
    /// Whether the page measured or moved after this report went: a word the view does not rest
    /// from, whatever the host answers.
    page_spoke: bool,
    /// Whether it asks for the place the view was opened with.
    restore: bool,
    /// Whether it is the return to the live screen that took the restore's place.
    superseding: bool,
    /// Whether the host answered that it cannot say what became of it. It holds the way until a
    /// screen settles it, and no answer is left to wait for.
    unknown: bool,
}

/// A move that has settled inside the view, waiting to be told to the page.
#[derive(Clone, Copy, Debug)]
struct Untold {
    /// The number of the last move it covers.
    last: u64,
    /// The revision a screen the page draws must name to hold it, or none for a move that changed
    /// nothing.
    revision: Option<u64>,
}

/// What a view opened with a place does about it. Nothing reaches the page until it is over.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Restore {
    /// Over, or none was asked.
    Done,
    /// Not sent: it goes first, on the first screen, when that screen is of the anchor's buffer and
    /// width.
    Queued(Anchor),
    /// The one report in flight, with the newest revision any answer or screen named when it went.
    Sent { anchor: Anchor, seen: u64 },
    /// The host could not say what became of it. It is in flight still, and a window revision above
    /// `seen` is its own: the view never claims geometry, the window is at home before it, and
    /// reports of one connection are taken in order.
    Unknown { anchor: Anchor, seen: u64 },
    /// Settled, and waiting for a complete screen to be judged.
    Answered { anchor: Anchor, how: How },
    /// A return to the live screen was taken before it was over: the person's word is final, no note
    /// is made and no restore is ever made after it. It is over once that return settles and a
    /// screen shows where the window is. `origin` is where the return puts the window.
    Superseded { origin: Record, live: Live },
}

/// How a restore was answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    /// Accepted: the window is at a revision at or above this.
    Landed(u64),
    /// Never made: refused, refused for now, not asked for or dropped.
    NotMade,
}

/// The return to the live screen that took a restore's place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Live {
    /// Not settled.
    Settling,
    /// Settled: the window is at this revision, or the host did not take it.
    Settled(Option<u64>),
}

/// What the end of a restore says to the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// What to say of the place the window landed at.
    pub note: Option<Note>,
}

/// Where one view's window is, and the viewport reports it owes the session.
///
/// Every report the view sends goes through here, one at a time. What goes next is one choice,
/// asked after every event: the newest size if it is not the size last sent, or if a report of it
/// was not settled, else the place the view was opened with, else the next run of moves. Nothing
/// goes while a report is in flight, while a new subscription is being asked for, whose first screen
/// is what says where the window then is, while a size the host did not take for now rests, or, once
/// a screen has arrived, while the view holds no complete one; before the first, only a size goes,
/// from where the attach put the window. No move goes while a restore is not over.
#[derive(Debug)]
pub struct WindowReports {
    /// Where the window is, from the newest complete screen naming at least `answered`, and at the
    /// live screen's origin before any, or `None` while a recovery is under way.
    record: Option<Record>,
    /// The newest revision any answer has named. A screen of an earlier one is drawn for a window
    /// the view has since moved, and never moves the record.
    answered: u64,
    /// The revision the newest complete screen named.
    installed: Option<u64>,
    /// The report in flight, if any.
    in_flight: Option<InFlight>,
    /// Whether a new subscription has been asked for and its first screen has not arrived.
    recovering: bool,
    /// The newest size the page measured.
    size: Dimensions,
    /// The size the last report carried, or the attach's.
    size_sent: Dimensions,
    /// Moves not yet sent, in the order the page made them.
    runs: VecDeque<Run>,
    /// The number of the last move taken.
    taken: u64,
    /// Moves settled inside the view that the page has not been told of, in order.
    untold: VecDeque<Untold>,
    /// The newest move the page has been told is settled.
    told: u64,
    /// Whether the newest size is owed to the host whatever the size last sent was, because a
    /// report of it was not settled. The host may have the size of that report, so even the size
    /// last sent has to be said again.
    size_owed: bool,
    /// Whether a size the host did not take for now waits for something to arrive before it goes
    /// again, so that a host that keeps saying so is not asked in a loop.
    resting: bool,
    /// How many size reports in a row the host did not take for now.
    not_taken_in_a_row: u8,
    /// The place the view was opened with, until it is settled.
    restore: Restore,
    /// How the restore ended, until the view has read it.
    resolution: Option<Resolution>,
}

impl WindowReports {
    /// A view that attached at this size and holds no screen yet, and the place it asks the host
    /// for on its first screen.
    #[must_use]
    pub fn new(size: Dimensions, anchor: Option<Anchor>) -> Self {
        Self {
            record: Some(Record::ORIGIN),
            answered: 0,
            installed: None,
            in_flight: None,
            recovering: false,
            size,
            size_sent: size,
            runs: VecDeque::new(),
            taken: 0,
            untold: VecDeque::new(),
            told: 0,
            size_owed: false,
            resting: false,
            not_taken_in_a_row: 0,
            restore: anchor.map_or(Restore::Done, Restore::Queued),
            resolution: None,
        }
    }

    /// The page measured its grid at this size. Whatever the host did not take for now goes again
    /// with the next report chosen.
    pub const fn measured(&mut self, size: Dimensions) {
        self.size = size;
        self.page_spoke();
    }

    /// The host said something. A size it did not take for now goes again, as long as it has not
    /// failed to take it more than [`RETRIES`] times in a row since the page last spoke.
    pub const fn heard(&mut self) {
        if self.not_taken_in_a_row <= RETRIES {
            self.resting = false;
        }
    }

    /// The page spoke: a new start for whatever waits. A report in flight is told, so that its
    /// answer does not make the page's word wait.
    const fn page_spoke(&mut self) {
        self.resting = false;
        self.not_taken_in_a_row = 0;
        if let Some(flight) = self.in_flight.as_mut() {
            flight.page_spoke = true;
        }
    }

    /// The page moved the window. A move whose number is not above the last one taken is not one
    /// the page made after it, and is ignored.
    pub fn take(&mut self, asked: Move) {
        let number = asked.number();
        if number <= self.taken {
            return;
        }
        self.taken = number;
        self.page_spoke();
        match asked {
            Move::Pan { across, down, .. } => {
                if let Some(Run::Pan {
                    across: run_across,
                    down: run_down,
                    last,
                }) = self.runs.back_mut()
                    && run_across.signum() * across.signum() >= 0
                    && run_down.signum() * down.signum() >= 0
                {
                    *run_across = run_across.saturating_add(across);
                    *run_down = run_down.saturating_add(down);
                    *last = number;
                } else {
                    self.runs.push_back(Run::Pan {
                        across,
                        down,
                        last: number,
                    });
                }
            }
            Move::Live { number } => self.take_live(number),
        }
    }

    /// The page asked for the live screen. A restore that is not over gives way to it: the pans the
    /// person made against the place it was to restore are not made, since the window is not known
    /// to be there, and the return goes to where the anchor would be after one, whatever the
    /// restore did.
    fn take_live(&mut self, number: u64) {
        let anchor = match std::mem::replace(&mut self.restore, Restore::Done) {
            Restore::Done => {
                self.runs.push_back(Run::Live {
                    number,
                    absolute: None,
                });
                return;
            }
            superseded @ Restore::Superseded { .. } => {
                self.restore = superseded;
                self.runs.push_back(Run::Live {
                    number,
                    absolute: None,
                });
                return;
            }
            Restore::Queued(anchor) => {
                // Nothing was asked for: a return to the start has nothing to send.
                self.skip_pans();
                let Some(live) = anchor.live_of() else {
                    self.runs.push_back(Run::Skip { last: number });
                    self.finish(None);
                    return;
                };
                live
            }
            Restore::Sent { anchor, .. }
            | Restore::Unknown { anchor, .. }
            | Restore::Answered { anchor, .. } => {
                self.skip_pans();
                if let Some(flight) = self.in_flight
                    && flight.restore
                    && flight.unknown
                {
                    // The host has said all it will about it.
                    self.in_flight = None;
                }
                anchor.live_of().unwrap_or(anchor)
            }
        };
        let (origin, absolute) = if anchor.live_of().is_some() {
            (
                Record::from_anchor(&anchor),
                (anchor.position(), anchor.column()),
            )
        } else {
            (Record::ORIGIN, (None, 0))
        };
        self.restore = Restore::Superseded {
            origin,
            live: Live::Settling,
        };
        self.runs.push_back(Run::Live {
            number,
            absolute: Some(absolute),
        });
    }

    /// A move that is not made is settled where it stands in the order.
    fn skip_pans(&mut self) {
        for run in &mut self.runs {
            if let Run::Pan { last, .. } = *run {
                *run = Run::Skip { last };
            }
        }
        self.spend_skips();
    }

    /// Settles the moves not made that nothing stands before.
    fn spend_skips(&mut self) {
        while let Some(Run::Skip { last }) = self.runs.front().copied() {
            self.runs.pop_front();
            self.untold.push_back(Untold {
                last,
                revision: None,
            });
        }
    }

    /// The restore is over, and the view is to be told how.
    fn finish(&mut self, note: Option<Note>) {
        self.restore = Restore::Done;
        self.resolution = Some(Resolution { note });
    }

    /// The person took control with no return to the live screen: a restore not yet sent is not
    /// made, and the pans made against the place it was to restore are not either. A restore
    /// already sent is not touched.
    pub fn drop_queued_restore(&mut self) {
        if matches!(self.restore, Restore::Queued(_)) {
            self.skip_pans();
            self.finish(None);
        }
    }

    /// Whether the page is held back from every screen: the restore is not over, or the view has
    /// not yet read how it ended.
    #[must_use]
    pub const fn holds_restore(&self) -> bool {
        !matches!(self.restore, Restore::Done) || self.resolution.is_some()
    }

    /// Whether the report in flight is the restore's, so that an answer that cannot be read is not
    /// taken for a refusal.
    #[must_use]
    pub fn restore_in_flight(&self) -> bool {
        self.in_flight.is_some_and(|flight| flight.restore)
    }

    /// The number of the last move taken.
    #[must_use]
    pub const fn taken(&self) -> u64 {
        self.taken
    }

    /// How the restore ended, once, when the view has not read it yet.
    pub const fn take_resolution(&mut self) -> Option<Resolution> {
        self.resolution.take()
    }

    /// Ends the restore when its outcome is known and `screen`, the newest complete one the view
    /// holds, can be judged, and settles the pans made behind it: they stand or fall together with
    /// it. A restore that landed on the anchor's own place and column, with no note, lets them go,
    /// measured from there; every other end, and a return to the live screen that landed anywhere
    /// but where it was to, does not, since the window is not where the person aimed them.
    pub fn resolve(&mut self, screen: Option<&Screen>) {
        let (note, pans_made) = match &self.restore {
            Restore::Answered {
                how: How::NotMade, ..
            } => (Some(Note::Unavailable), false),
            Restore::Answered {
                anchor,
                how: How::Landed(revision),
            } => {
                let Some(screen) = screen.filter(|screen| screen.window_revision >= *revision)
                else {
                    return;
                };
                let note = anchor.judge(screen);
                let on_place = Record::of(screen) == Record::from_anchor(anchor);
                (note, note.is_none() && on_place)
            }
            Restore::Superseded {
                origin,
                live: Live::Settled(landed),
            } => {
                // A screen older than the newest answer is drawn for a window the view has since
                // moved, and says nothing of where it is.
                let Some(screen) = screen.filter(|screen| screen.window_revision >= self.answered)
                else {
                    return;
                };
                (None, landed.is_some() && Record::of(screen) == *origin)
            }
            _ => return,
        };
        if !pans_made {
            self.skip_pans();
        }
        self.finish(note);
    }

    /// A screen arrived whole: the revision of the window it is drawn for, and the screen.
    pub fn installed(&mut self, screen: &Screen) {
        let revision = screen.window_revision;
        self.installed = Some(revision);
        // While a subscription replaces another, the one being replaced delivers nothing here, so a
        // screen that arrives is the new subscription's, and the recovery is over.
        self.recovering = false;
        // A window revision above the one that was newest when a restore of unknown outcome went
        // is the restore's own.
        if let Restore::Unknown { anchor, seen } = &self.restore
            && revision > *seen
        {
            self.restore = Restore::Answered {
                anchor: anchor.clone(),
                how: How::Landed(revision),
            };
            self.answered = self.answered.max(revision);
            self.settle(Some(revision));
        }
        if revision >= self.answered {
            self.record = Some(Record::of(screen));
        }
        if let Some(InFlight {
            awaiting: Some(awaited),
            ..
        }) = self.in_flight
            && revision >= awaited
        {
            self.settle(Some(awaited));
        }
    }

    /// Whether a screen naming `revision`, just installed, must wait before the page may draw it:
    /// while a report is in flight without its answer, a screen newer than every answer may be that
    /// report's, and the page would draw its move twice. The answer comes next: the host queues a
    /// moved window's screen before it writes the answer.
    #[must_use]
    pub fn holds(&self, revision: u64) -> bool {
        matches!(
            self.in_flight,
            Some(InFlight {
                request: Some(_),
                awaiting: None,
                unknown: false,
                ..
            })
        ) && revision > self.answered
    }

    /// The view discarded its screen and asked for a new subscription. Until that one's first
    /// screen arrives nothing says where the window is, and nothing is sent.
    pub const fn recovering(&mut self) {
        self.record = None;
        self.recovering = true;
    }

    /// The report to send now, if any, measured against `screen`, the newest the view holds. It is
    /// in flight from here until it settles.
    ///
    /// A restore that is settled here, because the first screen is not of the anchor's buffer and
    /// width, is not sent: the view reads how it ended with [`Self::take_resolution`] and is
    /// not asked a thing.
    pub fn next(&mut self, screen: Option<&Screen>) -> Option<Sending> {
        self.resolve(screen);
        if self.recovering || self.in_flight.is_some() || self.resting {
            return None;
        }
        let record = self.record?;
        // Before the first screen the window is where the attach put it. After it, a reset can move
        // the window, so nothing goes while the view holds no complete screen.
        if screen.is_none() && self.installed.is_some() {
            return None;
        }
        let (sending, carries, restore, superseding) =
            if self.size == self.size_sent && !self.size_owed {
                let screen = screen?;
                if let Restore::Queued(anchor) = &self.restore {
                    if anchor.claims(screen) {
                        let sending = Sending {
                            dimensions: self.size_sent,
                            position: anchor.position(),
                            column: anchor.column(),
                        };
                        self.restore = Restore::Sent {
                            anchor: anchor.clone(),
                            seen: self.answered.max(self.installed.unwrap_or(0)),
                        };
                        self.in_flight = Some(InFlight {
                            request: None,
                            awaiting: None,
                            carries: None,
                            page_spoke: false,
                            restore: true,
                            superseding: false,
                            unknown: false,
                        });
                        return Some(sending);
                    }
                    self.restore = Restore::Answered {
                        anchor: anchor.clone(),
                        how: How::NotMade,
                    };
                    self.resolve(Some(screen));
                }
                loop {
                    let run = self.runs.front().copied()?;
                    // Nothing goes behind a restore that is not over, but the return that took its
                    // place.
                    if !matches!(self.restore, Restore::Done)
                        && !matches!(
                            run,
                            Run::Live {
                                absolute: Some(_),
                                ..
                            }
                        )
                    {
                        return None;
                    }
                    self.runs.pop_front();
                    match run {
                        Run::Live {
                            number,
                            absolute: Some((position, column)),
                        } => {
                            break (
                                Sending {
                                    dimensions: self.size_sent,
                                    position,
                                    column,
                                },
                                Some(number),
                                false,
                                true,
                            );
                        }
                        Run::Live {
                            number,
                            absolute: None,
                        } => match record.place {
                            Place::History(_) => {
                                break (
                                    Sending {
                                        dimensions: self.size_sent,
                                        position: None,
                                        column: record.column,
                                    },
                                    Some(number),
                                    false,
                                    false,
                                );
                            }
                            // A window on the live screen stays where it is.
                            Place::Live(_) => self.untold.push_back(Untold {
                                last: number,
                                revision: None,
                            }),
                        },
                        Run::Skip { last } => self.untold.push_back(Untold {
                            last,
                            revision: None,
                        }),
                        Run::Pan { across, down, last } => {
                            // A movement the window cannot make is spent here, inside the same
                            // choice, so the run behind it goes now rather than waiting for
                            // something else.
                            match moved(record, across, down, screen) {
                                Some((position, column)) => {
                                    break (
                                        Sending {
                                            dimensions: self.size_sent,
                                            position,
                                            column,
                                        },
                                        Some(last),
                                        false,
                                        false,
                                    );
                                }
                                None => self.untold.push_back(Untold {
                                    last,
                                    revision: None,
                                }),
                            }
                        }
                    }
                }
            } else {
                (
                    Sending {
                        dimensions: self.size,
                        position: record.position(),
                        column: record.column,
                    },
                    None,
                    false,
                    false,
                )
            };
        self.size_sent = sending.dimensions;
        self.size_owed = false;
        self.in_flight = Some(InFlight {
            request: None,
            awaiting: None,
            carries,
            page_spoke: false,
            restore,
            superseding,
            unknown: false,
        });
        Some(sending)
    }

    /// The view sent the report `next` handed it, under this request.
    pub const fn sent(&mut self, request: RequestId) {
        if let Some(in_flight) = self.in_flight.as_mut() {
            in_flight.request = Some(request);
        }
    }

    /// Whether `request` is the report in flight.
    #[must_use]
    pub fn is_in_flight(&self, request: RequestId) -> bool {
        self.in_flight
            .is_some_and(|in_flight| in_flight.request == Some(request))
    }

    /// The session answered the report in flight.
    ///
    /// A definite refusal settles it and changes nothing. A refusal for now, or an answer that
    /// cannot say what became of the report, settles a move the same way, but not a size: the newest
    /// size is owed again, with the next word from the host or the page, or at once when the page
    /// spoke while the report was in flight. An acceptance settles it once a screen naming its
    /// revision, or a later one, has arrived, whether that screen came before the answer or comes
    /// after it.
    ///
    /// A restore is the person's place and not the person's gesture. A refusal of any kind means it
    /// was not made, and it is never sent again. An answer that cannot say what became of it leaves
    /// it in flight: a window revision above every one seen when it went is its own.
    pub fn answered(&mut self, answer: Answer) {
        let restore = self.restore_in_flight();
        match answer {
            Answer::Refused => {
                self.not_taken_in_a_row = 0;
                self.restore_not_made();
                self.settle(None);
            }
            Answer::NotSettled if restore => {
                self.restore_not_made();
                self.settle(None);
            }
            Answer::NotSettled => self.not_taken(),
            Answer::Unknown if restore => self.restore_unknown(),
            Answer::Unknown => self.not_taken(),
            Answer::Accepted { window_revision } => {
                self.not_taken_in_a_row = 0;
                self.answered = self.answered.max(window_revision);
                if let Restore::Sent { anchor, .. } | Restore::Unknown { anchor, .. } =
                    &self.restore
                    && restore
                {
                    self.restore = Restore::Answered {
                        anchor: anchor.clone(),
                        how: How::Landed(window_revision),
                    };
                }
                if self
                    .installed
                    .is_some_and(|installed| installed >= window_revision)
                {
                    self.settle(Some(window_revision));
                } else if let Some(in_flight) = self.in_flight.as_mut() {
                    in_flight.awaiting = Some(window_revision);
                }
            }
        }
    }

    /// The restore in flight was refused: it was not made.
    fn restore_not_made(&mut self) {
        if !self.restore_in_flight() {
            return;
        }
        if let Restore::Sent { anchor, .. } | Restore::Unknown { anchor, .. } = &self.restore {
            self.restore = Restore::Answered {
                anchor: anchor.clone(),
                how: How::NotMade,
            };
        }
    }

    /// The host could not say what became of the restore in flight.
    fn restore_unknown(&mut self) {
        match &self.restore {
            Restore::Sent { anchor, seen } => {
                let (anchor, seen) = (anchor.clone(), *seen);
                match self.installed {
                    // A screen of a newer revision arrived while the restore was in flight: that is
                    // the restore's, and no further snapshot will come.
                    Some(installed) if installed > seen => {
                        self.restore = Restore::Answered {
                            anchor,
                            how: How::Landed(installed),
                        };
                        self.answered = self.answered.max(installed);
                        self.settle(Some(installed));
                    }
                    _ => {
                        self.restore = Restore::Unknown { anchor, seen };
                        if let Some(in_flight) = self.in_flight.as_mut() {
                            in_flight.unknown = true;
                        }
                    }
                }
            }
            // The return that took its place has the host's last word on it: the report is over.
            _ => self.in_flight = None,
        }
    }

    /// The host did not take the report in flight for now, or could not say what became of it.
    fn not_taken(&mut self) {
        let Some(flight) = self.in_flight else {
            return;
        };
        if flight.carries.is_some() {
            // A move is the person's gesture, and is not made later on their behalf: it is settled
            // as not taken, and they move again.
            self.not_taken_in_a_row = 0;
            self.settle(None);
            return;
        }
        // A size the host did not take is not settled: the newest size is owed again, whatever the
        // size last sent was, since the host may have taken the one this report carried. It waits
        // for something to arrive, unless the page spoke while the report was in flight.
        self.in_flight = None;
        self.size_owed = true;
        self.not_taken_in_a_row = self.not_taken_in_a_row.saturating_add(1);
        self.resting = !flight.page_spoke;
        // A restore that has not been sent is not made on a size the host does not take: the
        // window is not known to be where the restore would leave it.
        if let Restore::Queued(anchor) = &self.restore {
            self.restore = Restore::Answered {
                anchor: anchor.clone(),
                how: How::NotMade,
            };
        }
    }

    /// The report in flight settled: the moves it carried changed the window to `revision`, or
    /// changed nothing.
    fn settle(&mut self, revision: Option<u64>) {
        if let Some(flight) = self.in_flight {
            if let Some(last) = flight.carries {
                self.untold.push_back(Untold { last, revision });
            }
            if flight.superseding
                && let Restore::Superseded { live, .. } = &mut self.restore
            {
                *live = Live::Settled(revision);
            }
        }
        self.in_flight = None;
    }

    /// The newest move the page may take as settled, when the screen it draws names `drawn`: the
    /// moves settled inside the view, in order, as far as that screen holds them. A move that
    /// changed the window is held by a screen naming at least the revision it changed it to; a move
    /// that changed nothing is held by any.
    pub fn told(&mut self, drawn: Option<u64>) -> u64 {
        while let Some(untold) = self.untold.front().copied() {
            let held = untold
                .revision
                .is_none_or(|revision| drawn.is_some_and(|drawn| drawn >= revision));
            if !held {
                break;
            }
            self.untold.pop_front();
            self.told = untold.last;
        }
        self.told
    }
}

/// Where a run of `across` columns and `down` rows takes a window from `record`, measured against
/// the limits of `screen`, the newest the view holds: the place a report names and the column, or
/// `None` when the window cannot move at all.
///
/// Rows go between the oldest row the session keeps and the live screen's last line that still
/// fills the window; the alternate buffer numbers its own rows and keeps no history, so its oldest
/// row is its live screen's first. Columns go between the first and the last that still fills the
/// window. A place on the live screen is named by its line, which the host keeps as a line as the
/// session writes. A place above it is named by a row the window is already in the history, and by
/// its distance above the live screen from a window on it, which the host measures when the report
/// arrives; a move from the history onto the live screen takes its line from the newest live screen
/// the view holds.
fn moved(
    record: Record,
    across: i64,
    down: i64,
    screen: &Screen,
) -> Option<(Option<ViewportPosition>, u64)> {
    let live_top = i128::from(screen.viewport.screen_top_row.get());
    let oldest = i128::from(screen.oldest_retained_row);
    let rows = i128::from(screen.dimensions.rows.get());
    let columns = i128::from(screen.dimensions.columns.get());
    let shown_rows = i128::from(screen.viewport.rows.get()).min(rows);
    let shown_columns = i128::from(screen.viewport.columns.get()).min(columns);
    // Rows are measured from the live screen's first line, so a place in the history is below 0.
    let top = match record.place {
        Place::Live(line) => i128::from(line),
        Place::History(row) => i128::from(row) - live_top,
    };
    let highest = (oldest - live_top).min(0);
    let lowest = (rows - shown_rows).max(0);
    let target = (top + i128::from(down)).clamp(highest, lowest);
    let column =
        (i128::from(record.column) + i128::from(across)).clamp(0, (columns - shown_columns).max(0));
    if target == top && column == i128::from(record.column) {
        return None;
    }
    let position = if target > 0 {
        Some(ViewportPosition::Line(U64::new(
            u64::try_from(target).unwrap_or(u64::MAX),
        )))
    } else if target == 0 {
        None
    } else {
        match record.place {
            Place::Live(_) => Some(ViewportPosition::Above(U64::new(
                u64::try_from(-target).unwrap_or(u64::MAX),
            ))),
            Place::History(_) => Some(ViewportPosition::Row(U64::new(
                u64::try_from(live_top + target).unwrap_or(0),
            ))),
        }
    };
    Some((position, u64::try_from(column).unwrap_or(0)))
}
