//! Screens, read back as text.
//!
//! Two views of one session are compared by what a person would read on them: each visible row as
//! text, placed at its canonical columns, with trailing blanks dropped. A paired device holds the
//! session's screen as a projection or as the bytes its restoration and its live output were;
//! `kr attach` draws the screen into a terminal, which is read back through the product's own
//! terminal engine.

use kr_client::projection::Projection;
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig};

/// A terminal model fed with bytes: what a terminal of this size shows after being sent them.
pub struct Terminal {
    engine: Engine,
    started: std::time::Instant,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Terminal").finish_non_exhaustive()
    }
}

impl Terminal {
    /// A terminal of `columns` by `rows` that has been sent nothing.
    ///
    /// # Panics
    ///
    /// Panics when the engine cannot be made at that size.
    #[must_use]
    pub fn new(columns: u16, rows: u16) -> Self {
        let engine = Engine::new(EngineConfig {
            size: GridSize {
                cols: u32::from(columns),
                rows: u32::from(rows),
            },
            ..EngineConfig::default()
        })
        .expect("a terminal engine of that size");
        Self {
            engine,
            started: std::time::Instant::now(),
        }
    }

    /// Sends the terminal `bytes`.
    pub fn feed(&mut self, bytes: &[u8]) {
        let now = self.now();
        let _ = self.engine.feed(bytes, now);
    }

    /// The visible rows, as text.
    #[must_use]
    pub fn rows(&mut self) -> Vec<String> {
        let now = self.now();
        let _ = self.engine.quiesce(now);
        self.engine
            .grid()
            .visible_rows()
            .iter()
            .map(|row| {
                line(
                    row.runs
                        .iter()
                        .map(|run| (u64::from(run.column), run.text.as_str())),
                )
            })
            .collect()
    }

    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// The visible rows of a projection, as text, or nothing while it holds no screen.
#[must_use]
pub fn projection_rows(projection: &Projection) -> Option<Vec<String>> {
    let screen = projection.screen()?;
    Some(
        screen
            .visible_rows()
            .into_iter()
            .map(|row| {
                screen.row(row).map_or_else(String::new, |row| {
                    line(
                        row.runs
                            .iter()
                            .map(|run| (run.column.get(), run.text.as_str())),
                    )
                })
            })
            .collect(),
    )
}

/// Places runs of text at their columns and drops the blanks at the end.
fn line<'a>(runs: impl Iterator<Item = (u64, &'a str)>) -> String {
    let mut text = String::new();
    let mut width = 0_u64;
    for (column, run) in runs {
        while width < column {
            text.push(' ');
            width += 1;
        }
        text.push_str(run);
        width += u64::try_from(run.chars().count()).unwrap_or(0);
    }
    text.trim_end().to_owned()
}

/// The rows of a screen that carry anything, trailing empty rows dropped, for a comparison that
/// does not depend on how many blank rows follow the last line.
#[must_use]
pub fn content(rows: &[String]) -> Vec<String> {
    let mut rows = rows.to_vec();
    while rows.last().is_some_and(String::is_empty) {
        rows.pop();
    }
    rows
}

/// Whether any visible row carries `needle`.
#[must_use]
pub fn shows(rows: &[String], needle: &str) -> bool {
    rows.iter().any(|row| row.contains(needle))
}
