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

/// The most the titles and the virtual stack can hold.
///
/// Both bounds are fixed, so this is a figure rather than a measurement: it is what a session
/// reserves for its titles when its geometry is admitted, which is why a title is never refused.
/// A string is counted at twice the bytes it may hold, which is the most a doubling allocator
/// keeps for it, and the stack at twice its depth in slots, which is the most its array rounds up
/// to.
pub const MAX_RESIDENT_BYTES: u64 = {
    let handle = size_of::<String>() as u64;
    let title = 2 * MAX_TITLE_BYTES as u64;
    let current = 2 * (handle + title);
    let slots = 2 * MAX_DEPTH as u64 * size_of::<SavedTitle>() as u64;
    let saved = MAX_DEPTH as u64 * 2 * title;
    current + slots + saved
};

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

/// One entry on the virtual stack.
///
/// A push saves only the titles it names, so a field is either a title that was saved or nothing at
/// all. Those are different: a pop must leave the current title alone where nothing was saved, and
/// must set it to the empty string where an empty title was. Storing both as a plain string loses
/// that distinction and turns a selective push into a way to clear a title it never touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedTitle {
    /// The icon title, when this entry saved one.
    pub icon: Option<String>,
    /// The window title, when this entry saved one.
    pub window: Option<String>,
}

/// The session's titles and its virtual stack.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TitleState {
    current: TitleEntry,
    stack: Vec<SavedTitle>,
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

    /// Sets a title.
    ///
    /// A title longer than the per-entry bound is truncated on a character boundary. Returns
    /// whether it was, because a terminal reading the same bytes would have kept the whole thing
    /// and the two would then disagree about what the window is called.
    pub fn set(&mut self, target: TitleTarget, title: &str) -> bool {
        let value = truncate(title);
        let truncated = value.len() < title.len();
        match target {
            TitleTarget::Icon => self.current.icon = value,
            TitleTarget::Window => self.current.window = value,
            TitleTarget::Both => {
                self.current.icon = value.clone();
                self.current.window = value;
            }
        }
        truncated
    }

    /// Pushes the current titles, `CSI 22 t`.
    ///
    /// At the bound the oldest entry is dropped, not the newest: an application that pushes in a
    /// loop keeps its most recent nesting, and the stack stays bounded either way.
    pub fn push(&mut self, target: TitleTarget) {
        let mut entry = SavedTitle::default();
        match target {
            TitleTarget::Icon => entry.icon = Some(self.current.icon.clone()),
            TitleTarget::Window => entry.window = Some(self.current.window.clone()),
            TitleTarget::Both => {
                entry.icon = Some(self.current.icon.clone());
                entry.window = Some(self.current.window.clone());
            }
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
    ///
    /// The entry is discarded whether or not it held the title that was asked for, which is what a
    /// physical terminal does: the stack is one stack of entries, not one stack per title. Where
    /// the top entry did not save the title being asked for, the entries below it are searched, so
    /// a selective push followed by a selective pop of the other title still restores what it saved.
    pub fn pop(&mut self, target: TitleTarget) -> bool {
        let Some(entry) = self.stack.pop() else {
            self.underflows = self.underflows.saturating_add(1);
            return false;
        };
        if matches!(target, TitleTarget::Icon | TitleTarget::Both) {
            if let Some(icon) = entry.icon {
                self.current.icon = icon;
            } else if let Some(icon) = self.take_saved(|entry| entry.icon.take()) {
                self.current.icon = icon;
            }
        }
        if matches!(target, TitleTarget::Window | TitleTarget::Both) {
            if let Some(window) = entry.window {
                self.current.window = window;
            } else if let Some(window) = self.take_saved(|entry| entry.window.take()) {
                self.current.window = window;
            }
        }
        true
    }

    /// Takes the most recently saved value of one title from the entries still on the stack.
    fn take_saved(
        &mut self,
        mut pick: impl FnMut(&mut SavedTitle) -> Option<String>,
    ) -> Option<String> {
        for entry in self.stack.iter_mut().rev() {
            if let Some(value) = pick(entry) {
                return Some(value);
            }
        }
        None
    }

    /// The saved entries, oldest first, for a snapshot.
    #[must_use]
    pub fn entries(&self) -> &[SavedTitle] {
        &self.stack
    }

    /// What the titles and the virtual stack are holding.
    ///
    /// The room the strings and the stack are keeping rather than the characters they show. A
    /// stack that grew to its depth and then had entries popped still has the array it grew, and a
    /// measurement that counted the entries left on it would report a session as having given back
    /// something it is still holding.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        let handle = size_of::<String>() as u64;
        let mut bytes = 2 * handle
            + self.current.icon.capacity() as u64
            + self.current.window.capacity() as u64;
        bytes += (self.stack.capacity() * size_of::<SavedTitle>()) as u64;
        for entry in &self.stack {
            bytes += entry.icon.as_ref().map_or(0, |title| title.capacity()) as u64;
            bytes += entry.window.as_ref().map_or(0, |title| title.capacity()) as u64;
        }
        bytes
    }

    /// Restores a snapshot's titles and stack.
    ///
    /// Every title goes through the same per-entry bound a title from the session does. A snapshot
    /// is state this session once held, but it arrives from outside, and a restoration that took
    /// it at its word could put back more than a session is allowed to hold.
    pub fn restore(&mut self, current: TitleEntry, stack: Vec<SavedTitle>, underflows: u32) {
        self.current = TitleEntry {
            icon: truncate(&current.icon),
            window: truncate(&current.window),
        };
        self.stack = stack;
        self.stack.truncate(MAX_DEPTH);
        for entry in &mut self.stack {
            entry.icon = entry.icon.as_deref().map(truncate);
            entry.window = entry.window.as_deref().map(truncate);
        }
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
