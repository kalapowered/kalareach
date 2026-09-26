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
    /// it has settled.
    Live { number: u64 },
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
    /// Refused: nothing changed.
    Refused,
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
    /// The number of the last move it carries, when it carries any.
    carries: Option<u64>,
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

/// Where one view's window is, and the viewport reports it owes the session.
///
/// Every report the view sends goes through here, one at a time. What goes next is one choice,
/// asked after every event: the newest size if it is not the size last sent, else the next run of
/// moves. Nothing goes while a report is in flight, while a new subscription is being asked for,
/// whose first screen is what says where the window then is, or, once a screen has arrived, while
/// the view holds no complete one; before the first, only a size goes, from where the attach put
/// the window.
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
}

impl WindowReports {
    /// A view that attached at this size and holds no screen yet.
    #[must_use]
    pub const fn new(size: Dimensions) -> Self {
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
        }
    }

    /// The page measured its grid at this size.
    pub const fn measured(&mut self, size: Dimensions) {
        self.size = size;
    }

    /// The page moved the window. A move whose number is not above the last one taken is not one
    /// the page made after it, and is ignored.
    pub fn take(&mut self, asked: Move) {
        let number = match asked {
            Move::Pan { number, .. } | Move::Live { number } => number,
        };
        if number <= self.taken {
            return;
        }
        self.taken = number;
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
            Move::Live { number } => self.runs.push_back(Run::Live { number }),
        }
    }

    /// A screen arrived whole: the revision of the window it is drawn for, and the screen.
    pub fn installed(&mut self, screen: &Screen) {
        let revision = screen.window_revision;
        self.installed = Some(revision);
        // While a subscription replaces another, the one being replaced delivers nothing here, so a
        // screen that arrives is the new subscription's, and the recovery is over.
        self.recovering = false;
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
    pub fn next(&mut self, screen: Option<&Screen>) -> Option<Sending> {
        if self.recovering || self.in_flight.is_some() {
            return None;
        }
        let record = self.record?;
        // Before the first screen the window is where the attach put it. After it, a reset can move
        // the window, so nothing goes while the view holds no complete screen.
        if screen.is_none() && self.installed.is_some() {
            return None;
        }
        let (sending, carries) = if self.size == self.size_sent {
            let screen = screen?;
            loop {
                let run = self.runs.front().copied()?;
                self.runs.pop_front();
                match run {
                    Run::Live { number } => match record.place {
                        Place::History(_) => {
                            break (
                                Sending {
                                    dimensions: self.size_sent,
                                    position: None,
                                    column: record.column,
                                },
                                Some(number),
                            );
                        }
                        // A window on the live screen stays where it is.
                        Place::Live(_) => self.untold.push_back(Untold {
                            last: number,
                            revision: None,
                        }),
                    },
                    Run::Pan { across, down, last } => {
                        // A movement the window cannot make is spent here, inside the same choice,
                        // so the run behind it goes now rather than waiting for something else.
                        match moved(record, across, down, screen) {
                            Some((position, column)) => {
                                break (
                                    Sending {
                                        dimensions: self.size_sent,
                                        position,
                                        column,
                                    },
                                    Some(last),
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
            )
        };
        self.size_sent = sending.dimensions;
        self.in_flight = Some(InFlight {
            request: None,
            awaiting: None,
            carries,
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
    /// A refusal settles it and changes nothing. An acceptance settles it once a screen naming its
    /// revision, or a later one, has arrived, whether that screen came before the answer or comes
    /// after it.
    pub fn answered(&mut self, answer: Answer) {
        match answer {
            Answer::Refused => self.settle(None),
            Answer::Accepted { window_revision } => {
                self.answered = self.answered.max(window_revision);
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

    /// The report in flight settled: the moves it carried changed the window to `revision`, or
    /// changed nothing.
    fn settle(&mut self, revision: Option<u64>) {
        if let Some(InFlight {
            carries: Some(last),
            ..
        }) = self.in_flight
        {
            self.untold.push_back(Untold { last, revision });
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
