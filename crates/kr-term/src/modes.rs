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

/// The DEC modes that all name the same thing: whether the alternate buffer is active.
pub const ALTERNATE_BUFFER_MODES: &[u16] = &[47, 1047, 1049];

/// Every mode the engine tracks, and the keyboard state that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeState {
    ansi: BTreeMap<u16, bool>,
    dec: BTreeMap<u16, bool>,
    keypad_application: bool,
    modify_other_keys: u8,
    /// The Kitty keyboard state of each buffer: primary first, alternate second.
    ///
    /// The protocol gives each screen its own stack, so a full-screen application's negotiation
    /// cannot leak into the shell's when it exits. One shared stack would leave the shell speaking
    /// a protocol it never asked for.
    kitty: [KittyState; 2],
    /// How many consoles on this stream have asked for win32 input and not yet disabled it.
    ///
    /// Counted rather than held as a flag, so that a console inside this session - `wsl.exe`, an
    /// `ssh` session, a nested ConPTY - cannot turn the owned backend's mode off when it ends.
    /// [`crate::win32::Nesting`] is where that rule lives.
    win32_input: crate::win32::Nesting,
}

/// One buffer's Kitty keyboard negotiation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KittyState {
    flags: Option<u8>,
    stack: Vec<u8>,
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
        for mode in ALTERNATE_BUFFER_MODES {
            dec.insert(*mode, false);
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
            kitty: [KittyState::default(), KittyState::default()],
            win32_input: crate::win32::Nesting::NONE,
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
                    if enabled {
                        self.win32_input.requested();
                    } else {
                        self.win32_input.disabled();
                    }
                    return true;
                }
                // Modes 47, 1047 and 1049 all name one thing: whether the alternate buffer is
                // active. Recording them separately would let the tracker disagree with the grid
                // about which screen is showing.
                if ALTERNATE_BUFFER_MODES.contains(&mode) {
                    for alias in ALTERNATE_BUFFER_MODES {
                        self.dec.insert(*alias, enabled);
                    }
                    return true;
                }
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
                    return self.win32_input.is_on();
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
                        return if self.win32_input.is_on() {
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
        self.win32_input.is_on()
    }

    /// How many consoles on this stream have asked for win32 input and not yet disabled it.
    ///
    /// One is the owned backend's own request. More than one means a console inside the session
    /// has asked as well, and the disable that inner console sends when it ends leaves the outer
    /// backend's mode exactly where it was.
    #[must_use]
    pub const fn win32_input_nesting(&self) -> crate::win32::Nesting {
        self.win32_input
    }

    /// What this session can honestly say about the input it carries for the owned backend.
    ///
    /// The backend asked for records, or it did not. Nothing here claims a fidelity a client's
    /// input does not have: a client without console records sends legacy VT input on either path.
    #[must_use]
    pub const fn backend_input_fidelity(&self) -> crate::win32::Fidelity {
        if self.win32_input.is_on() {
            crate::win32::Fidelity::Records
        } else {
            crate::win32::Fidelity::LegacyVt
        }
    }

    /// The `modifyOtherKeys` level.
    #[must_use]
    pub const fn modify_other_keys(&self) -> u8 {
        self.modify_other_keys
    }

    /// Records a `modifyOtherKeys` resource change. Only resource 4 is qualified.
    ///
    /// `CSI > m` with no resource resets every resource to its initial value, and `CSI > 4 m` with
    /// no value resets that one. Both mean level zero here.
    pub const fn set_modify_other_keys(&mut self, resource: Option<u8>, value: Option<u8>) -> bool {
        match resource {
            None => {
                self.modify_other_keys = 0;
                true
            }
            Some(4) => {
                self.modify_other_keys = match value {
                    None => 0,
                    Some(level) if level > 2 => 2,
                    Some(level) => level,
                };
                true
            }
            Some(_) => false,
        }
    }

    /// Which buffer's keyboard negotiation is in force.
    fn kitty_slot(&self) -> usize {
        usize::from(self.is_set(ModeKind::Dec, 1049))
    }

    /// The active Kitty keyboard flags, when the protocol is in use.
    #[must_use]
    pub fn kitty_flags(&self) -> Option<u8> {
        self.kitty[self.kitty_slot()].flags
    }

    /// Pushes Kitty keyboard flags, keeping only the qualified bits.
    pub fn push_kitty(&mut self, flags: u8) {
        let slot = self.kitty_slot();
        let state = &mut self.kitty[slot];
        if state.stack.len() >= KITTY_STACK_DEPTH {
            state.stack.remove(0);
        }
        state.stack.push(state.flags.unwrap_or(0));
        state.flags = Some(flags & KITTY_QUALIFIED_FLAGS);
    }

    /// Pops `count` entries from the Kitty keyboard flag stack.
    ///
    /// The protocol's default is one entry, and so is an explicit zero, because a parameter of zero
    /// takes the sequence's default.
    pub fn pop_kitty(&mut self, count: usize) {
        let slot = self.kitty_slot();
        let state = &mut self.kitty[slot];
        for _ in 0..count.max(1) {
            match state.stack.pop() {
                Some(previous) => state.flags = Some(previous),
                None => {
                    state.flags = None;
                    break;
                }
            }
        }
    }

    /// Sets the Kitty keyboard flags in place, honouring the set, or, and and modes.
    pub fn set_kitty(&mut self, flags: u8, mode: u8) {
        let qualified = flags & KITTY_QUALIFIED_FLAGS;
        let slot = self.kitty_slot();
        let state = &mut self.kitty[slot];
        let current = state.flags.unwrap_or(0);
        let next = match mode {
            2 => current | qualified,
            3 => current & !qualified,
            _ => qualified,
        };
        state.flags = Some(next);
    }

    /// The encoding an input path must produce to control this application.
    ///
    /// An attachment that cannot produce it is refused rather than allowed to send an encoding the
    /// application does not accept.
    #[must_use]
    pub fn keyboard_encoding(&self) -> KeyboardEncoding {
        match self.kitty_flags() {
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
    /// DECSTR touches a named set of state and leaves the rest alone, and the tracker resets
    /// exactly what the canonical grid resets. Resetting more would put the two out of step in the
    /// other direction, which is just as wrong as resetting less.
    ///
    /// The set is: application cursor keys (1), reverse video (5), origin mode (6), autowrap (7,
    /// which DECSTR sets rather than clears, following xterm), reverse wraparound (45), the keypad
    /// (66), left and right margin mode (69), insert mode (4), the alternate buffer, the character
    /// sets and `modifyOtherKeys`. Line feed mode, the cursor modes, the mouse modes, bracketed
    /// paste, synchronised output and the backend's own input mode all survive.
    pub fn soft_reset(&mut self) {
        for mode in [1u16, 5, 6, 45, 69] {
            self.dec.insert(mode, false);
        }
        self.dec.insert(7, true);
        self.set_keypad_application(false);
        self.ansi.insert(4, false);
        for alias in ALTERNATE_BUFFER_MODES {
            self.dec.insert(*alias, false);
        }
        self.modify_other_keys = 0;
    }

    /// The active buffer's Kitty keyboard flag stack, oldest first, for a snapshot.
    #[must_use]
    pub fn kitty_stack(&self) -> &[u8] {
        &self.kitty[self.kitty_slot()].stack
    }

    /// One buffer's Kitty keyboard negotiation, for a snapshot.
    ///
    /// Both buffers are carried, because a restored session may leave the alternate buffer later
    /// and has to speak what the primary buffer negotiated when it does.
    #[must_use]
    pub fn kitty_buffer(&self, alternate: bool) -> (Option<u8>, Vec<u8>) {
        let state = &self.kitty[usize::from(alternate)];
        (state.flags, state.stack.clone())
    }

    /// Restores the keyboard negotiation state from a snapshot.
    ///
    /// Every entry goes through the same bound an entry from the session does. A snapshot is state
    /// this session once held, but it arrives from outside, and a restoration that took it at its
    /// word could put back flags the profile does not advertise or a stack deeper than one a
    /// session can build.
    pub fn restore_keyboard(&mut self, modify_other_keys: u8, buffers: [(Option<u8>, Vec<u8>); 2]) {
        self.modify_other_keys = modify_other_keys.min(2);
        for (slot, (flags, stack)) in buffers.into_iter().enumerate() {
            let state = &mut self.kitty[slot];
            state.flags = flags.map(|flags| flags & KITTY_QUALIFIED_FLAGS);
            // Into an array of exactly the entries kept, not the one that arrived: a vector
            // carries the room it was built with, and a snapshot could have been built with a
            // great deal of it.
            state.stack = stack
                .into_iter()
                .take(KITTY_STACK_DEPTH)
                .map(|entry| entry & KITTY_QUALIFIED_FLAGS)
                .collect();
            state.stack.shrink_to_fit();
        }
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
        out.push((ModeKind::Dec, MODE_WIN32_INPUT, self.win32_input.is_on()));
        out
    }
}

impl Default for ModeState {
    fn default() -> Self {
        Self::new()
    }
}
