//! A model of a person's physical terminal: what one of the xterm family shows after it is sent
//! some bytes, and every side effect it performs.
//!
//! The profile's own engine reads everything but the buffer switches. A qualified terminal is of
//! the xterm family, and a restoration switches its buffers with modes 47, 1047 and 1049 as that
//! family defines them. The profile does not include mode 47 (section 8 lists the modes it does,
//! and the engine consumes a request for one it does not), so an engine of the profile cannot stand
//! in for such a terminal at a switch. This model keeps each buffer in an engine of its own, reads
//! the switches itself, and hands every other byte to the engine of the buffer showing at that
//! moment:
//!
//! | Sequence | What the terminal does |
//! | --- | --- |
//! | `CSI ? 47 h` / `CSI ? 47 l` | shows the alternate / primary buffer; nothing is cleared |
//! | `CSI ? 1047 h` | shows the alternate buffer |
//! | `CSI ? 1047 l` | clears the alternate buffer when it is showing, then shows the primary one |
//! | `CSI ? 1049 h` | saves the cursor as DECSC does, shows the alternate buffer and clears it |
//! | `CSI ? 1049 l` | shows the primary buffer and restores the cursor as DECRC does |
//!
//! Both buffers live as long as the terminal, so whatever one restoration leaves in a buffer is
//! there for the next one to clear or not.

use kr_client::projection::ProjectedModeSpelling;
use kr_protocol::projection::ProjectedBuffer;
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::sideeffect::SideEffectKind;

use crate::screen::View;

/// The modes that all say which buffer is showing.
const BUFFER_MODES: [u64; 3] = [47, 1047, 1049];

/// A buffer switch a terminal of the xterm family reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Switch {
    Show47Alternate,
    Show47Primary,
    Enter1047,
    Leave1047,
    Enter1049,
    Leave1049,
}

const SWITCHES: [(&[u8], Switch); 6] = [
    (b"\x1b[?1049h", Switch::Enter1049),
    (b"\x1b[?1049l", Switch::Leave1049),
    (b"\x1b[?1047h", Switch::Enter1047),
    (b"\x1b[?1047l", Switch::Leave1047),
    (b"\x1b[?47h", Switch::Show47Alternate),
    (b"\x1b[?47l", Switch::Show47Primary),
];

/// What one feed made the terminal do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Performed {
    /// The side effects, in order.
    pub effects: Vec<SideEffectKind>,
    /// Side effects it refused, as a person would name them.
    pub refused: Vec<String>,
    /// How many questions it answered.
    pub replies: usize,
}

/// A terminal of the xterm family, modelled on the profile's engine.
pub struct Terminal {
    /// The primary buffer, then the alternate one.
    buffers: [Engine; 2],
    /// Which of the two is showing.
    showing: usize,
    /// The start of a switch sequence the last feed ended inside, held until the rest arrives.
    held: Vec<u8>,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Terminal")
            .field("showing", &self.showing)
            .finish_non_exhaustive()
    }
}

impl Terminal {
    /// A terminal of `columns` by `rows` that has been sent nothing.
    ///
    /// # Errors
    ///
    /// Returns what the engine refused about the size.
    pub fn new(columns: u16, rows: u16) -> Result<Self, String> {
        let buffer = || {
            Engine::new(EngineConfig {
                size: GridSize {
                    cols: u32::from(columns),
                    rows: u32::from(rows),
                },
                ..EngineConfig::DEFAULT
            })
            .map_err(|error| format!("a terminal of {columns}x{rows}: {error}"))
        };
        Ok(Self {
            buffers: [buffer()?, buffer()?],
            showing: 0,
            held: Vec::new(),
        })
    }

    /// Sends the terminal `bytes`, and says what it did.
    pub fn feed(&mut self, bytes: &[u8]) -> Performed {
        let mut input = std::mem::take(&mut self.held);
        input.extend_from_slice(bytes);
        let mut performed = Performed::default();
        let mut start = 0;
        let mut at = 0;
        while at < input.len() {
            if input[at] != 0x1b {
                at += 1;
                continue;
            }
            let rest = &input[at..];
            if let Some((sequence, switch)) = SWITCHES
                .iter()
                .find(|(sequence, _)| rest.starts_with(sequence))
            {
                self.send(&input[start..at], &mut performed);
                self.switch(*switch, &mut performed);
                at += sequence.len();
                start = at;
                continue;
            }
            if SWITCHES
                .iter()
                .any(|(sequence, _)| sequence.starts_with(rest))
            {
                // The feed ends part way into what may be a switch: the rest decides.
                self.send(&input[start..at], &mut performed);
                self.held = rest.to_vec();
                return performed;
            }
            at += 1;
        }
        self.send(&input[start..], &mut performed);
        performed
    }

    fn send(&mut self, bytes: &[u8], performed: &mut Performed) {
        if bytes.is_empty() {
            return;
        }
        let outcome = self.buffers[self.showing].feed(bytes, 0);
        let settled = self.buffers[self.showing].quiesce(0);
        for outcome in [outcome, settled] {
            performed
                .effects
                .extend(outcome.side_effects.into_iter().map(|effect| effect.kind));
            performed.refused.extend(
                outcome
                    .refusals
                    .iter()
                    .map(|refusal| format!("a refused side effect ({refusal:?})")),
            );
            performed.replies += outcome.responses;
        }
    }

    fn switch(&mut self, switch: Switch, performed: &mut Performed) {
        match switch {
            Switch::Show47Alternate | Switch::Enter1047 => self.showing = 1,
            Switch::Show47Primary => self.showing = 0,
            Switch::Leave1047 => {
                if self.showing == 1 {
                    self.send(b"\x1b[2J", performed);
                }
                self.showing = 0;
            }
            Switch::Enter1049 => {
                self.send(b"\x1b7", performed);
                self.showing = 1;
                self.send(b"\x1b[2J", performed);
            }
            Switch::Leave1049 => {
                self.showing = 0;
                self.send(b"\x1b8", performed);
            }
        }
    }

    /// What the terminal shows, and holds in the buffer that is not showing.
    ///
    /// # Errors
    ///
    /// Returns what reading either buffer's engine refused.
    pub fn view(&mut self) -> Result<View, String> {
        let active = if self.showing == 1 {
            ProjectedBuffer::Alternate
        } else {
            ProjectedBuffer::Primary
        };
        let other = if self.showing == 1 {
            ProjectedBuffer::Primary
        } else {
            ProjectedBuffer::Alternate
        };
        let hidden = View::of_engine(&mut self.buffers[1 - self.showing], 0)?;
        let mut view = View::of_engine(&mut self.buffers[self.showing], 0)?;
        // Each engine only ever shows its own first buffer, so the cursor it saved belongs to the
        // buffer it stands for here.
        for saved in &mut view.saved {
            saved.buffer = active;
        }
        let mut saved = view.saved.clone();
        saved.extend(hidden.saved.iter().cloned().map(|mut saved| {
            saved.buffer = other;
            saved
        }));
        saved.sort_by_key(|saved| saved.buffer);
        view.saved = saved;
        view.active = active;
        for mode in BUFFER_MODES {
            view.modes
                .insert((ProjectedModeSpelling::Dec, mode), self.showing == 1);
        }
        Ok(view.with_other(hidden.lines))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[crate::screen::Line]) -> Vec<String> {
        lines.iter().map(crate::screen::Line::text).collect()
    }

    #[test]
    fn mode_47_switches_without_clearing_and_1049_clears_the_alternate_buffer_on_entry() {
        let mut terminal = Terminal::new(12, 3).expect("a terminal");
        let _ = terminal.feed(b"primary\x1b[?47h\x1b[Halternate\x1b[?47l");
        let view = terminal.view().expect("a view");
        assert_eq!(view.active, ProjectedBuffer::Primary);
        assert_eq!(text(&view.lines)[0], "primary");
        assert_eq!(text(&view.other)[0], "alternate");
        let _ = terminal.feed(b"\x1b[?1049h");
        let view = terminal.view().expect("a view");
        assert_eq!(view.active, ProjectedBuffer::Alternate);
        assert_eq!(
            text(&view.lines)[0],
            "",
            "entering 1049 clears the alternate buffer"
        );
        assert_eq!(text(&view.other)[0], "primary");
    }

    #[test]
    fn a_switch_split_across_two_feeds_is_read_whole() {
        let mut terminal = Terminal::new(12, 3).expect("a terminal");
        let _ = terminal.feed(b"shell\x1b[?10");
        let _ = terminal.feed(b"49h\x1b[Happ");
        let view = terminal.view().expect("a view");
        assert_eq!(view.active, ProjectedBuffer::Alternate);
        assert_eq!(text(&view.lines)[0], "app");
        assert_eq!(text(&view.other)[0], "shell");
    }
}
