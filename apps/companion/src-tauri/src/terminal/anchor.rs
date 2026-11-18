//! Where a window was in a session, kept by the page between two openings of a terminal view and
//! judged by native code against the screen the host gives back.
//!
//! The page never reads an anchor. Native code mints it from the screen it publishes, the page keeps
//! it as it came, and the next view for the same session is opened with it: the view asks the host
//! for that place before it draws anything, and says so when the screen it was given does not show
//! the place the person left.
//!
//! An anchor holds a first row's stable identifier, the buffer, the width and the generation it was
//! taken in, and a value over the first row's cells. That detects a changed buffer, a changed width
//! or generation, and a first row whose text, blank or cut state differs. It does not claim the
//! identity of the whole reading position: after a width change and back, a first row that repeats
//! can match at a renumbered identifier.

use kr_client::projection::Screen;
use kr_protocol::attachment::ViewportPosition;
use kr_protocol::projection::{ProjectedBuffer, ProjectedRow};
use kr_protocol::scalars::U64;
use serde::{Deserialize, Serialize};

/// What native code says of the place a restored window landed at, when it is not the place the
/// person left.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Note {
    /// The row is older than the oldest the session keeps.
    Gone,
    /// The buffer, the width, the generation or the first row's content differs from the anchor's.
    Different,
    /// The place was not restored, or the screen the host gave does not hold the row.
    Unavailable,
}

/// Where an anchor's first row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorPlace {
    /// A row of the history, by its stable identifier.
    History(u64),
    /// A line of the live screen, counted from its first.
    Live(u64),
}

/// A window's place in a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    /// The history row, or none for a place on the live screen.
    #[serde(with = "decimal_option")]
    row: Option<u64>,
    /// The line of the live screen, for a place on it; zero for a row of the history.
    line: u64,
    /// The first column.
    column: u64,
    /// The buffer the window was in.
    buffer: ProjectedBuffer,
    /// The width of the session's grid.
    columns: u64,
    /// The generation of the screen the anchor was taken from.
    #[serde(with = "decimal")]
    generation: u64,
    /// A value over the first row's cells, for a row of the history that is not blank or cut.
    #[serde(with = "decimal_option")]
    fingerprint: Option<u64>,
}

impl Anchor {
    /// The place of the window `screen` shows, or none for the live screen's first line and first
    /// column, where a view starts and which is never kept.
    #[must_use]
    pub fn of(screen: &Screen) -> Option<Self> {
        let viewport = &screen.viewport;
        let top = viewport.top_row.get();
        let live_top = viewport.screen_top_row.get();
        let column = viewport.left_column.get();
        let (row, line) = if top < live_top {
            (Some(top), 0)
        } else {
            (None, top - live_top)
        };
        if row.is_none() && line == 0 && column == 0 {
            return None;
        }
        Some(Self {
            row,
            line,
            column,
            buffer: screen.active_buffer,
            columns: screen.dimensions.columns.get(),
            generation: screen.generation,
            fingerprint: row
                .and_then(|row| fingerprint(screen.rows.get(&(screen.active_buffer, row)))),
        })
    }

    /// The place a return to the live screen leaves this one at: the live screen's first line at
    /// the same column, a place on the live screen as it is. None where that is the start.
    #[must_use]
    pub fn live_of(&self) -> Option<Self> {
        let live = match self.place() {
            AnchorPlace::Live(_) => self.clone(),
            AnchorPlace::History(_) => Self {
                row: None,
                line: 0,
                fingerprint: None,
                ..self.clone()
            },
        };
        (live.line != 0 || live.column != 0).then_some(live)
    }

    /// Whether the screen is of the buffer and the width the anchor was taken in. A place is asked
    /// for only on such a screen.
    #[must_use]
    pub fn claims(&self, screen: &Screen) -> bool {
        self.buffer == screen.active_buffer && self.columns == screen.dimensions.columns.get()
    }

    /// The anchor's own place.
    #[must_use]
    pub const fn place(&self) -> AnchorPlace {
        match self.row {
            Some(row) => AnchorPlace::History(row),
            None => AnchorPlace::Live(self.line),
        }
    }

    /// The first column.
    #[must_use]
    pub const fn column(&self) -> u64 {
        self.column
    }

    /// What a viewport report names to put a window at this place: none for the live screen's
    /// first line.
    #[must_use]
    pub const fn position(&self) -> Option<ViewportPosition> {
        match self.place() {
            AnchorPlace::History(row) => Some(ViewportPosition::Row(U64::new(row))),
            AnchorPlace::Live(0) => None,
            AnchorPlace::Live(line) => Some(ViewportPosition::Line(U64::new(line))),
        }
    }

    /// What `screen`, which the host gave back for a restore of this place, says of it, in this
    /// order: another buffer or width is a different session; a row older than the oldest the
    /// session keeps, in the same generation, is gone; a row among the rows shown is the place,
    /// where the first row's value is compared only across a generation change and only when both
    /// values exist; a row that is not shown is unavailable. A place on the live screen needs no
    /// more than the buffer and the width.
    #[must_use]
    pub fn judge(&self, screen: &Screen) -> Option<Note> {
        if !self.claims(screen) {
            return Some(Note::Different);
        }
        let AnchorPlace::History(row) = self.place() else {
            return None;
        };
        let same_generation = self.generation == screen.generation;
        if same_generation && row < screen.oldest_retained_row {
            return Some(Note::Gone);
        }
        let top = screen.viewport.top_row.get();
        if row >= top && row - top < screen.viewport.rows.get() {
            if same_generation {
                return None;
            }
            let now = fingerprint(screen.rows.get(&(screen.active_buffer, row)));
            return match (self.fingerprint, now) {
                (Some(then), Some(now)) if then == now => None,
                _ => Some(Note::Different),
            };
        }
        Some(Note::Unavailable)
    }
}

/// A 64-bit FNV-1a value over each run's column and text of the whole row the host sent, so that a
/// clipped window and the blanks a reverse-video screen draws do not reach it. None for a row that
/// is absent, cut, or has no text.
fn fingerprint(row: Option<&ProjectedRow>) -> Option<u64> {
    let row = row?;
    if row.truncated || row.runs.iter().all(|run| run.text.trim().is_empty()) {
        return None;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for run in &row.runs {
        let column = run.column.get().to_le_bytes();
        for byte in column.into_iter().chain(run.text.bytes()).chain([0xff]) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    Some(hash)
}

/// A `u64` as a decimal string, so that a page that holds numbers as doubles never rounds it.
mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// An optional `u64` as an optional decimal string.
mod decimal_option {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.collect_str(value),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| text.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}
