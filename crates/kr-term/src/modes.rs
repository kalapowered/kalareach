//! Tracked terminal modes, keypad state and keyboard protocol negotiation.
//!
//! The engine tracks every mode it advertises, because a reconnecting client has to be put back
//! into the same state and because the query broker answers mode queries from here rather than
//! from a physical terminal.
//!
//! Modes the profile does not implement are not silently tracked as though they worked. Asked
//! about one, the broker says "not recognised", which is what an application needs to hear in
//! order to fall back.

use std::collections::BTreeMap;

use crate::classify::{
    MODE_DECCOLM, MODE_GRAPHEME_CLUSTERING, MODE_INBAND_RESIZE, MODE_WIN32_INPUT,
    TRACKED_ANSI_MODES, TRACKED_DEC_MODES,
};

/// The DECRQM report status for one mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeReport {
    /// `0`: the profile does not recognise the mode.
    NotRecognised,
    /// `1`: set.
    Set,
    /// `2`: reset.
    Reset,
    /// `3`: always set and cannot be reset.
    PermanentlySet,
    /// `4`: always reset and cannot be set.
    PermanentlyReset,
}

impl ModeReport {
    /// The numeric status the reply carries.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::NotRecognised => 0,
            Self::Set => 1,
            Self::Reset => 2,
            Self::PermanentlySet => 3,
            Self::PermanentlyReset => 4,
        }
    }
}

/// Which spelling of a mode a sequence used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModeKind {
    /// `CSI Ps h` and `CSI Ps l`.
    Ansi,
    /// `CSI ? Ps h` and `CSI ? Ps l`.
    Dec,
}

/// The keyboard protocol an application has negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardEncoding {
    /// The legacy xterm encoding.
    Legacy,
    /// xterm `modifyOtherKeys` at the given level.
    ModifyOtherKeys(u8),
    /// The Kitty keyboard protocol with the given flags.
    Kitty(u8),
}

/// The qualified Kitty keyboard flags kr-vt/1 accepts.
///
/// Bit 1 disambiguates escape codes, bit 2 reports event types, bit 4 reports alternate keys and
/// bit 8 reports all keys as escape codes. Bit 16, text association, is not advertised: the
/// encoders on the client side are not qualified for it, and advertising a flag the input path
/// drops is exactly what section 8 forbids.
pub const KITTY_QUALIFIED_FLAGS: u8 = 0b0000_1111;

/// Depth of the Kitty keyboard flag stack.
const KITTY_STACK_DEPTH: usize = 16;

/// Every mode the engine tracks, and the keyboard state that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeState {
    ansi: BTreeMap<u16, bool>,
    dec: BTreeMap<u16, bool>,
    keypad_application: bool,
    modify_other_keys: u8,
    kitty_flags: Option<u8>,
    kitty_stack: Vec<u8>,
    win32_input: bool,
}

impl ModeState {
    /// The state a fresh session starts in.
    ///
    /// DEC modes 7 (autowrap), 12 (cursor blink) and 25 (cursor visible) start set, matching the
    /// pinned terminfo entry; everything else starts reset.
    #[must_use]
    pub fn new() -> Self {
        let mut dec = BTreeMap::new();
        for mode in TRACKED_DEC_MODES {
            dec.insert(*mode, matches!(mode, 7 | 12 | 25));
        }
        let mut ansi = BTreeMap::new();
        for mode in TRACKED_ANSI_MODES {
            ansi.insert(*mode, false);
        }
        Self {
            ansi,
            dec,
            keypad_application: false,
            modify_other_keys: 0,
            kitty_flags: None,
            kitty_stack: Vec::new(),
            win32_input: false,
        }
    }

    /// Records a set or reset of a tracked mode. Returns whether the mode is tracked at all.
    pub fn set(&mut self, kind: ModeKind, mode: u16, enabled: bool) -> bool {
        match kind {
            ModeKind::Ansi => match self.ansi.get_mut(&mode) {
                Some(slot) => {
                    *slot = enabled;
                    true
                }
                None => false,
            },
            ModeKind::Dec => {
                if mode == MODE_WIN32_INPUT {
                    self.win32_input = enabled;
                    return true;
                }
                // Modes 1047, 1048 and 1049 combine buffer switching with the saved cursor; the
                // canonical grid owns that, so only the observable flag is recorded here.
                match self.dec.get_mut(&mode) {
                    Some(slot) => {
                        *slot = enabled;
                        // DECNKM is the other spelling of the keypad state.
                        if mode == 66 {
                            self.keypad_application = enabled;
                        }
                        true
                    }
                    None => false,
                }
            }
        }
    }

    /// Whether a tracked mode is set.
    #[must_use]
    pub fn is_set(&self, kind: ModeKind, mode: u16) -> bool {
        match kind {
            ModeKind::Ansi => self.ansi.get(&mode).copied().unwrap_or(false),
            ModeKind::Dec => {
                if mode == MODE_WIN32_INPUT {
                    return self.win32_input;
                }
                self.dec.get(&mode).copied().unwrap_or(false)
            }
        }
    }

    /// The DECRQM answer for one mode.
    #[must_use]
    pub fn report(&self, kind: ModeKind, mode: u16) -> ModeReport {
        match kind {
            ModeKind::Ansi => match self.ansi.get(&mode) {
                Some(true) => ModeReport::Set,
                Some(false) => ModeReport::Reset,
                None => ModeReport::NotRecognised,
            },
            ModeKind::Dec => {
                // Their own rows in the class table. Each one is answered honestly rather than
                // tracked as though the profile implemented it.
                match mode {
                    MODE_DECCOLM => return ModeReport::PermanentlyReset,
                    MODE_GRAPHEME_CLUSTERING | MODE_INBAND_RESIZE => {
                        return ModeReport::NotRecognised;
                    }
                    MODE_WIN32_INPUT => {
                        return if self.win32_input {
                            ModeReport::Set
                        } else {
                            ModeReport::Reset
                        };
                    }
                    _ => {}
                }
                match self.dec.get(&mode) {
                    Some(true) => ModeReport::Set,
                    Some(false) => ModeReport::Reset,
                    None => ModeReport::NotRecognised,
                }
            }
        }
    }

    /// Whether the keypad is in application mode.
    #[must_use]
    pub const fn keypad_application(&self) -> bool {
        self.keypad_application
    }

    /// Records DECKPAM, DECKPNM or DEC mode 66, which all name the same state.
    pub fn set_keypad_application(&mut self, application: bool) {
        self.keypad_application = application;
        self.dec.insert(66, application);
    }

    /// Whether the ConPTY win32 input mode is on for the owned backend.
    #[must_use]
    pub const fn win32_input(&self) -> bool {
        self.win32_input
    }

    /// The `modifyOtherKeys` level.
    #[must_use]
    pub const fn modify_other_keys(&self) -> u8 {
        self.modify_other_keys
    }

    /// Records a `modifyOtherKeys` resource change. Only resource 4 is qualified.
    pub const fn set_modify_other_keys(&mut self, resource: u8, value: u8) -> bool {
        if resource != 4 {
            return false;
        }
        self.modify_other_keys = if value > 2 { 2 } else { value };
        true
    }

    /// The active Kitty keyboard flags, when the protocol is in use.
    #[must_use]
    pub fn kitty_flags(&self) -> Option<u8> {
        self.kitty_flags
    }

    /// Pushes Kitty keyboard flags, keeping only the qualified bits.
    pub fn push_kitty(&mut self, flags: u8) {
        if self.kitty_stack.len() >= KITTY_STACK_DEPTH {
            self.kitty_stack.remove(0);
        }
        self.kitty_stack.push(self.kitty_flags.unwrap_or(0));
        self.kitty_flags = Some(flags & KITTY_QUALIFIED_FLAGS);
    }

    /// Pops `count` entries from the Kitty keyboard flag stack.
    pub fn pop_kitty(&mut self, count: usize) {
        for _ in 0..count.max(1) {
            match self.kitty_stack.pop() {
                Some(previous) => self.kitty_flags = Some(previous),
                None => {
                    self.kitty_flags = None;
                    break;
                }
            }
        }
    }

    /// Sets the Kitty keyboard flags in place, honouring the set, or, and and modes.
    pub fn set_kitty(&mut self, flags: u8, mode: u8) {
        let qualified = flags & KITTY_QUALIFIED_FLAGS;
        let current = self.kitty_flags.unwrap_or(0);
        let next = match mode {
            2 => current | qualified,
            3 => current & !qualified,
            _ => qualified,
        };
        self.kitty_flags = Some(next);
    }

    /// The encoding an input path must produce to control this application.
    ///
    /// An attachment that cannot produce it is refused rather than allowed to send an encoding the
    /// application does not accept.
    #[must_use]
    pub fn keyboard_encoding(&self) -> KeyboardEncoding {
        match self.kitty_flags {
            Some(flags) if flags != 0 => KeyboardEncoding::Kitty(flags),
            _ => {
                if self.modify_other_keys > 0 {
                    KeyboardEncoding::ModifyOtherKeys(self.modify_other_keys)
                } else {
                    KeyboardEncoding::Legacy
                }
            }
        }
    }

    /// Applies a full reset: every mode returns to its initial value.
    pub fn full_reset(&mut self) {
        *self = Self::new();
    }

    /// Applies a soft reset.
    ///
    /// DECSTR returns the primary screen, which is what the canonical grid does, so the tracked
    /// buffer modes go with it. The backend's own input mode survives, because DECSTR comes from
    /// the application and the backend is not the application.
    pub fn soft_reset(&mut self) {
        let win32 = self.win32_input;
        *self = Self::new();
        self.win32_input = win32;
    }

    /// The Kitty keyboard flag stack, oldest first, for a snapshot.
    #[must_use]
    pub fn kitty_stack(&self) -> &[u8] {
        &self.kitty_stack
    }

    /// Restores the keyboard negotiation state from a snapshot.
    pub fn restore_keyboard(
        &mut self,
        modify_other_keys: u8,
        kitty_flags: Option<u8>,
        kitty_stack: Vec<u8>,
    ) {
        self.modify_other_keys = modify_other_keys.min(2);
        self.kitty_flags = kitty_flags.map(|flags| flags & KITTY_QUALIFIED_FLAGS);
        self.kitty_stack = kitty_stack;
        self.kitty_stack.truncate(KITTY_STACK_DEPTH);
    }

    /// Every tracked mode and its value, for a snapshot.
    #[must_use]
    pub fn tracked(&self) -> Vec<(ModeKind, u16, bool)> {
        let mut out = Vec::with_capacity(self.ansi.len() + self.dec.len() + 1);
        for (mode, value) in &self.ansi {
            out.push((ModeKind::Ansi, *mode, *value));
        }
        for (mode, value) in &self.dec {
            out.push((ModeKind::Dec, *mode, *value));
        }
        out.push((ModeKind::Dec, MODE_WIN32_INPUT, self.win32_input));
        out
    }
}

impl Default for ModeState {
    fn default() -> Self {
        Self::new()
    }
}
