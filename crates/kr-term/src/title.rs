//! The application title and its virtualised stack.
//!
//! An attach client saves the outer terminal's title before it hands the screen over, and restores
//! it on detach. A running application can push and pop titles as often as it likes; section 8
//! requires that none of that can reach the client's saved title. The stack here is the session's
//! own, it is bounded, and popping an empty stack yields the session's current title rather than
//! whatever the outer terminal had.

/// Maximum depth of the virtual title stack, matching the bound xterm applies.
pub const MAX_DEPTH: usize = 10;

/// Maximum length of one title, in bytes.
///
/// A title arrives inside a bounded control string, but the stack keeps titles resident, so the
/// per-entry bound is what stops repeated OSC updates from allocating without bound.
pub const MAX_TITLE_BYTES: usize = 1024;

/// Which title an OSC selector addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleTarget {
    /// The icon title, OSC 1.
    Icon,
    /// The window title, OSC 2.
    Window,
    /// Both, OSC 0.
    Both,
}

impl TitleTarget {
    /// The target an OSC selector addresses.
    #[must_use]
    pub const fn from_selector(selector: u32) -> Option<Self> {
        match selector {
            0 => Some(Self::Both),
            1 => Some(Self::Icon),
            2 => Some(Self::Window),
            _ => None,
        }
    }
}

/// One saved pair of titles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TitleEntry {
    /// The icon title.
    pub icon: String,
    /// The window title.
    pub window: String,
}

/// The session's titles and its virtual stack.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TitleState {
    current: TitleEntry,
    stack: Vec<TitleEntry>,
    /// How many pops found an empty stack. A snapshot carries this so the diagnostic survives.
    underflows: u32,
}

impl TitleState {
    /// A session with empty titles and an empty stack.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current icon title.
    #[must_use]
    pub fn icon(&self) -> &str {
        &self.current.icon
    }

    /// The current window title.
    #[must_use]
    pub fn window(&self) -> &str {
        &self.current.window
    }

    /// Current depth of the virtual stack.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// How many pops have found the stack empty.
    #[must_use]
    pub const fn underflows(&self) -> u32 {
        self.underflows
    }

    /// Sets a title. A title longer than the per-entry bound is truncated on a character boundary.
    pub fn set(&mut self, target: TitleTarget, title: &str) {
        let value = truncate(title);
        match target {
            TitleTarget::Icon => self.current.icon = value,
            TitleTarget::Window => self.current.window = value,
            TitleTarget::Both => {
                self.current.icon = value.clone();
                self.current.window = value;
            }
        }
    }

    /// Pushes the current titles, `CSI 22 t`.
    ///
    /// At the bound the oldest entry is dropped, not the newest: an application that pushes in a
    /// loop keeps its most recent nesting, and the stack stays bounded either way.
    pub fn push(&mut self, target: TitleTarget) {
        let mut entry = TitleEntry::default();
        match target {
            TitleTarget::Icon => entry.icon = self.current.icon.clone(),
            TitleTarget::Window => entry.window = self.current.window.clone(),
            TitleTarget::Both => entry = self.current.clone(),
        }
        if self.stack.len() == MAX_DEPTH {
            self.stack.remove(0);
        }
        self.stack.push(entry);
    }

    /// Pops the titles, `CSI 23 t`.
    ///
    /// Returns whether an entry was there. An empty stack leaves the current titles alone; it never
    /// reaches past the session into a client's saved title.
    pub fn pop(&mut self, target: TitleTarget) -> bool {
        let Some(entry) = self.stack.pop() else {
            self.underflows = self.underflows.saturating_add(1);
            return false;
        };
        match target {
            TitleTarget::Icon => self.current.icon = entry.icon,
            TitleTarget::Window => self.current.window = entry.window,
            TitleTarget::Both => self.current = entry,
        }
        true
    }

    /// The saved entries, oldest first, for a snapshot.
    #[must_use]
    pub fn entries(&self) -> &[TitleEntry] {
        &self.stack
    }

    /// Restores a snapshot's titles and stack.
    pub fn restore(&mut self, current: TitleEntry, stack: Vec<TitleEntry>, underflows: u32) {
        self.current = current;
        self.stack = stack;
        self.stack.truncate(MAX_DEPTH);
        self.underflows = underflows;
    }
}

fn truncate(title: &str) -> String {
    if title.len() <= MAX_TITLE_BYTES {
        return title.to_owned();
    }
    let mut end = MAX_TITLE_BYTES;
    while end > 0 && !title.is_char_boundary(end) {
        end -= 1;
    }
    title[..end].to_owned()
}
