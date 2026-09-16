//! Rendering a side-effect-free restoration into terminal bytes.
//!
//! The terminal engine describes a screen as [`RestoreOp`], a closed set of rendering operations
//! with no member that can ring, copy, notify, download, launch or ask anything. That closure is
//! the whole point: a session's history is full of things that *were* events when they happened,
//! and replaying its bytes would do all of them again to whoever is attached now.
//!
//! A client that keeps its own grid applies the operations directly. A client whose screen is a
//! real terminal cannot: it needs bytes. This module is that translation, and it is the only place
//! in the host that turns presentation state back into a byte stream.
//!
//! # What the translation can and cannot carry
//!
//! Everything a terminal can be told over its own wire is emitted: the buffer, the palette, the
//! modes, the keypad and keyboard negotiation, the tab stops, the character sets, the margins, the
//! rows with their renditions and hyperlinks, the current title, the saved cursor of the buffer
//! that is showing, the buffer that is not, and the cursor.
//!
//! The buffer that is not showing is painted by switching to it with `?47` and back before the
//! active buffer is drawn: `?47` moves between the two without clearing either, which `?1047` and
//! `?1049` do not.
//!
//! What a byte stream still cannot carry is named here rather than approximated, and every one of
//! them is counted in [`Restoration::carried`] rather than left for a caller to discover:
//!
//! * **The saved cursor and keyboard negotiation of the buffer that is not showing.** `DECSC` saves
//!   the state of the buffer in force, and the keyboard stack belongs to one buffer, so installing
//!   either for the other one means leaving the screen inside the wrong buffer.
//! * **The virtual title stack.** Pushing it onto the terminal's own stack would grow that stack
//!   on every repaint and could evict what the person's own terminal had saved. Only the current
//!   title is set.
//! * **Soft-wrap markers.** A row this writer draws itself is a hard row as far as the terminal is
//!   concerned, so a line the application wrapped is copied as two lines rather than one.
//! * **The right-hand side of a row wider than the window.** A terminal narrower than the session
//!   is shown the part it has room for; nothing is reflowed and nothing wraps into the next row.
//! * **A pending wrap.** Every cursor movement clears one and only printing into the last column
//!   sets one, so putting a terminal back into it would mean drawing that cell through whatever
//!   pen, character set, margin and origin the restoration has installed. The cost is one
//!   character: the next one the application prints lands beside the last column instead of
//!   wrapping to the next row.

use kr_term::grid::{Blink, Colour, GridRow, Rendition, Run, UnderlineStyle, VerticalPosition};
use kr_term::modes::ALTERNATE_BUFFER_MODES;
use kr_term::palette::Rgb;
use kr_term::sideeffect::{
    ClipboardSelection, NotificationDisplay, NotificationUrgency, Progress, SideEffectKind,
};
use kr_term::snapshot::{
    ActiveBuffer, Charsets, CursorState, Designations, KeyboardSnapshot, Margins, PaletteSnapshot,
    RestoreOp, SavedCursor, Viewport,
};

/// What a rendered restoration could not carry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Carried {
    /// Rows of the buffer that is not showing, which a byte stream cannot paint.
    pub inactive_rows: usize,
    /// Saved cursors belonging to the buffer that is not showing.
    pub other_saved_cursors: usize,
    /// Title-stack entries, which are held virtually rather than pushed onto the terminal's own.
    pub title_stack: usize,
    /// Rows whose right-hand side lies outside the window this terminal is looking at.
    pub clipped_rows: usize,
    /// Soft-wrap markers, which a byte stream cannot set on a row it has drawn itself.
    pub soft_wraps: usize,
    /// The keyboard negotiation of the buffer that is not showing.
    pub other_keyboard: bool,
    /// Keyboard-stack entries the session holds, which this restoration does not install.
    pub keyboard_stack: usize,
    /// A pending wrap this restoration could not reproduce.
    pub pending_wrap: bool,
}

impl Carried {
    /// Returns whether everything the operations described was emitted.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.inactive_rows == 0
            && self.other_saved_cursors == 0
            && self.title_stack == 0
            && self.clipped_rows == 0
            && self.soft_wraps == 0
            && !self.other_keyboard
            && self.keyboard_stack == 0
            && !self.pending_wrap
    }

    /// Returns whether a terminal given this restoration can be handed the raw stream afterwards.
    ///
    /// The same question as [`Carried::complete`], with one member left out. A row clipped to a
    /// narrower window is not this question: a terminal narrower than the session is never handed
    /// the stream in the first place, so a restoration that clipped is one for an attachment that
    /// is already projected. Everything else a restoration could not carry does decide it, and each
    /// for its own reason: a pending wrap decides whether the next character wraps or replaces the
    /// last cell, a saved cursor decides where a restore goes, a title stack decides what a pop
    /// shows, an inactive buffer and its keyboard negotiation decide what a switch back reveals,
    /// and a soft-wrap marker decides what a selection copies, which section 8 requires to stay
    /// correct after a reconnection.
    #[must_use]
    pub const fn continues_the_stream(self) -> bool {
        self.inactive_rows == 0
            && self.other_saved_cursors == 0
            && self.title_stack == 0
            && self.soft_wraps == 0
            && !self.other_keyboard
            && self.keyboard_stack == 0
            && !self.pending_wrap
    }
}

/// One rendered restoration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restoration {
    /// The bytes that put a terminal into the state the operations described.
    pub bytes: Vec<u8>,
    /// What the translation could not carry.
    pub carried: Carried,
}

/// Whether a restoration may change the terminal's keyboard protocols.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Keyboard {
    /// The session's keyboard state is installed, because this terminal said what it is and its
    /// own state was read before the attachment began, so it can be put back exactly.
    #[default]
    Install,
    /// Nothing about the keyboard is changed, because nobody was allowed to ask this terminal what
    /// it had negotiated and nothing else can put back what an install would take away.
    ///
    /// This is what an attachment that asked its terminal nothing is served: section 8's
    /// conservative profile is one that does not touch what it cannot restore. What the session
    /// holds is counted as something the restoration did not carry.
    Withhold,
}

/// What of the session's screen a restoration may carry.
///
/// Section 10's live-screen exception is exactly that: the currently visible screen, and never the
/// buffer that is not showing, the scrollback or the backing transcript. A caller whose authority
/// is that exception is served [`Scope::LiveScreen`], and the rows of the other buffer are counted
/// among what the restoration did not carry rather than painted into it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scope {
    /// Everything the snapshot describes, including the buffer that is not showing.
    #[default]
    WholeScreen,
    /// The currently visible screen only.
    LiveScreen,
}

/// Renders a restoration for a terminal showing `viewport` of the canonical grid.
///
/// The viewport decides which canonical rows land on which screen lines and which columns are
/// shown, so a terminal smaller than the session sees the part it is looking at rather than a
/// wrapped approximation of the whole. `keyboard` decides whether this terminal's keyboard
/// protocols may be changed at all, and `scope` decides how much of the screen this caller's
/// authority reaches.
#[must_use]
pub fn render(
    operations: &[RestoreOp],
    viewport: Viewport,
    keyboard: Keyboard,
    scope: Scope,
) -> Restoration {
    let mut writer = Writer::new(viewport, keyboard);
    writer.scope = scope;
    for operation in operations {
        writer.apply(operation);
    }
    writer.finish()
}

/// The escape introducer.
const ESC: u8 = 0x1B;

/// DEC private mode 6, origin mode, which changes what every absolute address means.
const ORIGIN_MODE: u16 = 6;

/// DEC private mode 1048, which is a cursor save and restore rather than a state to be left in.
const CURSOR_SAVE_MODE: u16 = 1048;
/// The string terminator this writer uses, which every profile in the repertoire accepts.
const ST: &[u8] = b"\x1b\\";

struct Writer {
    out: Vec<u8>,
    viewport: Viewport,
    /// How much of the screen this caller's authority reaches.
    scope: Scope,
    active: ActiveBuffer,
    /// The rendition the terminal is in, once this writer has put it in one.
    ///
    /// `None` until something sets it. A writer that assumed the terminal started plain would skip
    /// the first rendition when it happens to be the default one, and leave a row drawn in whatever
    /// the terminal already had.
    pen: Option<Rendition>,
    /// The hyperlink currently open, so a run does not reopen the one it is already inside.
    link: Option<String>,
    /// True once the snapshot's own open hyperlink has been installed, so it is not closed again.
    link_is_the_snapshots: bool,
    /// The character sets the application had selected, held back until the rows are painted.
    charsets: Option<Charsets>,
    /// The rows of the buffer that is not showing, held back until the switch can be made.
    inactive: Vec<GridRow>,
    /// The scroll region, held back until the rows have been painted.
    ///
    /// Every row is addressed absolutely, and an absolute address means something different once
    /// margins and origin mode are in force. The screen is therefore painted with neither, and both
    /// are installed afterwards together with the cursor, which is the only thing whose position
    /// they then apply to.
    /// Whether this terminal's keyboard protocols may be changed at all.
    keyboard: Keyboard,
    margins: Option<Margins>,
    /// Whether the snapshot had origin mode set, held back for the same reason.
    origin_mode: bool,
    carried: Carried,
}

impl Writer {
    fn new(viewport: Viewport, keyboard: Keyboard) -> Self {
        Self {
            out: Vec::new(),
            viewport,
            scope: Scope::WholeScreen,
            active: ActiveBuffer::Primary,
            pen: None,
            link: None,
            link_is_the_snapshots: false,
            charsets: None,
            inactive: Vec::new(),
            margins: None,
            origin_mode: false,
            keyboard,
            carried: Carried::default(),
        }
    }

    fn finish(mut self) -> Restoration {
        // A link the snapshot had open stays open: the next character the application prints
        // belongs to it. A link this writer opened only to draw a run does not.
        if self.link.is_some() && !self.link_is_the_snapshots {
            self.close_link();
        }
        Restoration {
            bytes: self.out,
            carried: self.carried,
        }
    }

    fn apply(&mut self, operation: &RestoreOp) {
        match operation {
            // A soft reset puts the terminal into a state this restoration then describes
            // completely. It is not a hard reset: that would clear the scrollback the person can
            // still scroll back through, and reset a palette the next operation sets anyway.
            RestoreOp::ResetProjection { .. } => {
                self.csi(b"!p");
                self.csi(b"2J");
                self.csi(b"H");
                // A soft reset leaves the terminal in the default rendition, which is a fact about
                // the terminal rather than an assumption about it.
                self.pen = Some(Rendition::default());
            }
            // The canonical size belongs to the session, not to this terminal. A terminal is never
            // told to resize itself: a viewport shows the part of the grid it can, and a direct
            // attachment already is the canonical size.
            RestoreOp::SetDimensions { .. } => {}
            RestoreOp::SelectBuffer { buffer } => {
                self.active = *buffer;
                match buffer {
                    ActiveBuffer::Primary => self.csi(b"?1049l"),
                    ActiveBuffer::Alternate => self.csi(b"?1049h"),
                }
            }
            RestoreOp::SetPalette { palette } => self.palette(palette),
            RestoreOp::SetMode { entry } => {
                if entry.kind == kr_term::modes::ModeKind::Dec {
                    // The alternate-buffer modes are the buffer selection under another spelling,
                    // and that has already been made. Setting them again here would clear the
                    // buffer this restoration is about to paint.
                    if ALTERNATE_BUFFER_MODES.contains(&entry.mode) {
                        return;
                    }
                    // 1048 is not a mode a terminal can be left in: setting it saves the cursor and
                    // clearing it restores one, either of which would overwrite the pen, the
                    // character sets and the origin this restoration is installing. The saved
                    // cursor is installed by its own operation instead.
                    if entry.mode == CURSOR_SAVE_MODE {
                        return;
                    }
                    // Origin mode changes what every absolute address afterwards means, and
                    // enabling it homes the cursor. It is installed with the margins, after the
                    // rows are painted.
                    if entry.mode == ORIGIN_MODE {
                        self.origin_mode = entry.enabled;
                        return;
                    }
                }
                let prefix: &[u8] = match entry.kind {
                    kr_term::modes::ModeKind::Ansi => b"",
                    kr_term::modes::ModeKind::Dec => b"?",
                };
                let suffix: &[u8] = if entry.enabled { b"h" } else { b"l" };
                let mut body = prefix.to_vec();
                body.extend_from_slice(entry.mode.to_string().as_bytes());
                body.extend_from_slice(suffix);
                self.csi(&body);
            }
            RestoreOp::SetKeypad { application } => {
                self.out.push(ESC);
                self.out.push(if *application { b'=' } else { b'>' });
            }
            RestoreOp::SetKeyboard { keyboard } => self.keyboard(keyboard),
            RestoreOp::SetTabStops { columns } => self.tab_stops(columns),
            // Held back with the margins. The rows carry canonical text, and a character set the
            // application selected afterwards would redraw that text as something else: an `q`
            // printed before DEC line drawing was selected is the letter, not a horizontal line.
            RestoreOp::SetCharsets { charsets } => self.charsets = Some(charsets.clone()),
            // Held back until the rows are painted; see the field's own note.
            RestoreOp::SetMargins { margins } => self.margins = Some(*margins),
            // Held back. The rows of the buffer that is not showing are painted in one run, by
            // switching to that buffer and back before the active buffer is painted, so the screen
            // this restoration is drawing is never left half drawn while the other one is filled.
            RestoreOp::PaintInactiveRow { row } => self.inactive.push(row.clone()),
            RestoreOp::PaintRow { row } => {
                self.paint_inactive_buffer();
                self.paint(row);
            }
            // Inert metadata. The runs of each row carry the link they belong to, and this writer
            // opens and closes it around them, so a terminal already has every range this names.
            RestoreOp::RecordHyperlink { .. } => {}
            RestoreOp::SetTitle { title, stack } => {
                // The stack stays virtual. Pushing it onto the terminal's own would grow that stack
                // by its whole depth on every repaint, and could evict a title the person's
                // terminal had saved for itself.
                self.carried.title_stack += stack.len();
                self.osc(b"1", title.icon.as_bytes());
                self.osc(b"2", title.window.as_bytes());
            }
            RestoreOp::SetRendition { rendition } => self.rendition(*rendition),
            RestoreOp::SetHyperlink { uri } => {
                match uri {
                    Some(uri) => self.open_link(uri),
                    None => {
                        if self.link.is_some() {
                            self.close_link();
                        }
                    }
                }
                // Whatever this leaves open is the link the application has open, so the next
                // character it prints belongs to it and this writer does not close it again.
                self.link_is_the_snapshots = uri.is_some();
            }
            RestoreOp::SetSavedCursor { cursor } => self.saved_cursor(cursor),
            RestoreOp::SetCursor { cursor } => self.cursor(*cursor),
        }
    }

    /// Writes one CSI sequence.
    fn csi(&mut self, body: &[u8]) {
        self.out.push(ESC);
        self.out.push(b'[');
        self.out.extend_from_slice(body);
    }

    /// Writes one OSC command, terminated with ST.
    ///
    /// The payload is the engine's own state, never a byte a caller supplied, but a control
    /// character inside a string would end the command early and leave the rest as screen text, so
    /// they are dropped rather than passed on.
    fn osc(&mut self, number: &[u8], payload: &[u8]) {
        osc_into(&mut self.out, number, payload);
    }

    /// Writes one OSC command that carries no parameter at all.
    ///
    /// A command with an empty parameter and one with no parameter are two different commands:
    /// `OSC 104` with nothing after it resets every indexed colour, and `OSC 104 ;` asks about an
    /// index that is not there.
    fn osc_bare(&mut self, number: &[u8]) {
        self.out.push(ESC);
        self.out.push(b']');
        self.out.extend_from_slice(number);
        self.out.extend_from_slice(ST);
    }

    fn palette(&mut self, palette: &PaletteSnapshot) {
        // Every indexed colour goes back to the terminal's own default first. Applying only the
        // session's overrides would leave an index this terminal had been given earlier and the
        // session has since put back, because a colour that matches the default is not an override
        // and so says nothing at all.
        self.osc_bare(b"104");
        for (index, colour) in &palette.overrides {
            let mut body = index.to_string().into_bytes();
            body.push(b';');
            body.extend_from_slice(&rgb_specification(*colour));
            self.osc(b"4", &body);
        }
        self.osc(b"10", &rgb_specification(palette.foreground));
        self.osc(b"11", &rgb_specification(palette.background));
        self.osc(b"12", &rgb_specification(palette.cursor));
        self.osc(b"13", &rgb_specification(palette.pointer_foreground));
        self.osc(b"14", &rgb_specification(palette.pointer_background));
        self.osc(b"17", &rgb_specification(palette.selection_background));
        self.osc(b"19", &rgb_specification(palette.selection_foreground));
    }

    fn keyboard(&mut self, keyboard: &KeyboardSnapshot) {
        let (kitty, other) = match self.active {
            ActiveBuffer::Primary => (&keyboard.primary, &keyboard.alternate),
            ActiveBuffer::Alternate => (&keyboard.alternate, &keyboard.primary),
        };
        if self.keyboard == Keyboard::Withhold {
            // Nobody was allowed to ask this terminal what it had negotiated, so nothing here
            // changes it: a level or a flag installed now could not be put back, and a person left
            // in an encoding their shell does not expect is the failure they cannot work around.
            // What the session holds is counted as something this restoration did not carry, which
            // is what keeps such an attachment on a projection.
            if keyboard.modify_other_keys != 0 || kitty.flags.is_some() {
                self.carried.other_keyboard = true;
            }
            self.carried.keyboard_stack += kitty.stack.len();
            return;
        }
        let mut body = b">".to_vec();
        body.extend_from_slice(b"4;");
        body.extend_from_slice(keyboard.modify_other_keys.to_string().as_bytes());
        body.push(b'm');
        self.csi(&body);
        // The other buffer's negotiation has no sequence that installs it without switching to that
        // buffer, which a restoration must not do.
        if other.flags.is_some() || !other.stack.is_empty() {
            self.carried.other_keyboard = true;
        }
        // What is installed is the flags in force, and nothing else. The terminal's keyboard stack
        // is not this session's: the attachment that borrowed the terminal saved its owner's own
        // negotiation there before any of this arrived, and emptying it or pushing onto it would
        // take that away or bury it. A stack the session holds is therefore counted as something
        // this restoration did not carry, which is what keeps such an attachment projected rather
        // than handed the stream with a stack it would pop into somebody else's state.
        // The flags are always installed, including none of them. A terminal reached by a
        // restoration is not a terminal that started empty: what an earlier application negotiated
        // there stays in force until something says otherwise, and a session whose own flags are
        // none would otherwise leave the application reading an encoding it never asked for.
        let mut set = b"=".to_vec();
        set.extend_from_slice(kitty.flags.unwrap_or(0).to_string().as_bytes());
        set.extend_from_slice(b";1u");
        self.csi(&set);
        self.carried.keyboard_stack += kitty.stack.len();
    }

    fn tab_stops(&mut self, columns: &[u32]) {
        self.csi(b"3g");
        for column in columns {
            if *column < self.viewport.left_col
                || *column >= self.viewport.left_col.saturating_add(self.viewport.cols)
            {
                continue;
            }
            let screen = column - self.viewport.left_col;
            self.move_to(0, screen);
            self.out.push(ESC);
            self.out.push(b'H');
        }
    }

    /// Writes the character-set designations and the shift state.
    ///
    /// Rows are painted before this runs, under whatever the terminal already had; the profile's
    /// reset leaves that as ASCII with the shift-out set inactive, which is what canonical text is.
    fn charsets(&mut self, charsets: &Charsets) {
        self.designations(&Designations {
            g0: charsets.g0.clone(),
            g1: charsets.g1.clone(),
        });
        self.out.push(if charsets.shift_out { 0x0E } else { 0x0F });
    }

    /// Writes the character-set designations, leaving the locking shift as it is.
    fn designations(&mut self, designations: &Designations) {
        if let Some(byte) = designation(&designations.g0) {
            self.out.push(ESC);
            self.out.push(b'(');
            self.out.push(byte);
        }
        if let Some(byte) = designation(&designations.g1) {
            self.out.push(ESC);
            self.out.push(b')');
            self.out.push(byte);
        }
    }

    fn paint(&mut self, row: &GridRow) {
        let Some(line) = self.line_of(row.stable_id) else {
            return;
        };
        self.move_to(line, 0);
        // The row is drawn from an empty line, so a shorter row does not leave the tail of
        // whatever the terminal had there before.
        self.csi(b"K");
        let mut clipped = false;
        for run in &row.runs {
            clipped |= self.run(run);
        }
        if clipped {
            self.carried.clipped_rows += 1;
        }
        // A row the application wrapped is drawn as a row of its own, because a terminal has no
        // sequence that marks one. Copying it will produce two lines rather than one.
        if row.soft_wrapped {
            self.carried.soft_wraps += 1;
        }
    }

    fn run(&mut self, run: &Run) -> bool {
        let Some(column) = self.column_of(run.column) else {
            // The run begins to the right of the window. Nothing of it is shown, and the row it
            // belongs to is reported as clipped.
            return run.column >= self.viewport.left_col;
        };
        // What the window has room for, in cells. Drawing a run wider than that would wrap into
        // the row below and, on the last row, scroll the screen this restoration is drawing.
        let room = self.viewport.cols.saturating_sub(column);
        let (text, clipped) = clip_to_cells(&run.text, room as usize);
        if text.is_empty() {
            return clipped;
        }
        self.move_to_column(column);
        self.rendition(run.rendition);
        match run.hyperlink.as_ref() {
            Some(uri) => self.open_link(uri),
            None => {
                if self.link.is_some() {
                    self.close_link();
                }
            }
        }
        // Control characters cannot appear in a run: the grid holds graphemes, not bytes. Dropping
        // anything below the space keeps that true of this writer as well, so no row can carry a
        // sequence back into the stream it was parsed out of.
        self.out.extend(
            text.chars()
                .filter(|character| !character.is_control())
                .flat_map(|character| {
                    let mut buffer = [0_u8; 4];
                    character.encode_utf8(&mut buffer).as_bytes().to_vec()
                }),
        );
        clipped
    }

    fn rendition(&mut self, rendition: Rendition) {
        if self.pen == Some(rendition) {
            return;
        }
        // One reset and then the whole rendition, rather than the difference. A difference would
        // be shorter and would also depend on the terminal agreeing about what the previous
        // rendition left set, which is exactly the assumption a restoration exists to avoid.
        let mut parameters: Vec<String> = vec!["0".to_owned()];
        if rendition.bold {
            parameters.push("1".to_owned());
        }
        if rendition.faint {
            parameters.push("2".to_owned());
        }
        if rendition.italic {
            parameters.push("3".to_owned());
        }
        match rendition.underline {
            UnderlineStyle::None => {}
            UnderlineStyle::Single => parameters.push("4".to_owned()),
            UnderlineStyle::Double => parameters.push("21".to_owned()),
            UnderlineStyle::Curly => parameters.push("4:3".to_owned()),
            UnderlineStyle::Dotted => parameters.push("4:4".to_owned()),
            UnderlineStyle::Dashed => parameters.push("4:5".to_owned()),
        }
        match rendition.blink {
            Blink::None => {}
            Blink::Slow => parameters.push("5".to_owned()),
            Blink::Rapid => parameters.push("6".to_owned()),
        }
        if rendition.reverse {
            parameters.push("7".to_owned());
        }
        if rendition.invisible {
            parameters.push("8".to_owned());
        }
        if rendition.strikethrough {
            parameters.push("9".to_owned());
        }
        if rendition.overline {
            parameters.push("53".to_owned());
        }
        match rendition.vertical_align {
            VerticalPosition::Baseline => {}
            VerticalPosition::Superscript => parameters.push("73".to_owned()),
            VerticalPosition::Subscript => parameters.push("74".to_owned()),
        }
        if let Some(parameter) = colour_parameter(rendition.foreground, 30, 90, 38) {
            parameters.push(parameter);
        }
        if let Some(parameter) = colour_parameter(rendition.background, 40, 100, 48) {
            parameters.push(parameter);
        }
        if let Colour::Direct(rgb) = rendition.underline_colour {
            parameters.push(format!("58:2::{}:{}:{}", rgb.r, rgb.g, rgb.b));
        } else if let Colour::Indexed(index) = rendition.underline_colour {
            parameters.push(format!("58:5:{index}"));
        }
        let mut body = parameters.join(";").into_bytes();
        body.push(b'm');
        self.csi(&body);
        self.pen = Some(rendition);
    }

    fn open_link(&mut self, uri: &str) {
        if self.link.as_deref() == Some(uri) {
            return;
        }
        let mut body = b";".to_vec();
        body.extend_from_slice(uri.as_bytes());
        self.osc(b"8", &body);
        self.link = Some(uri.to_owned());
    }

    fn close_link(&mut self) {
        self.osc(b"8", b";");
        self.link = None;
    }

    fn saved_cursor(&mut self, cursor: &SavedCursor) {
        // `DECSC` saves the state of the buffer that is showing, so the other buffer's saved cursor
        // has no sequence that installs it. It is reported rather than approximated.
        if cursor.buffer != self.active {
            self.carried.other_saved_cursors += 1;
            return;
        }
        let Some(line) = self.line_of_row(cursor.row) else {
            self.carried.other_saved_cursors += 1;
            return;
        };
        let Some(column) = self.column_of(cursor.col) else {
            self.carried.other_saved_cursors += 1;
            return;
        };
        let restore_pen = self.pen.unwrap_or_default();
        let restore_link = self.link.clone();
        self.csi(if cursor.origin_mode { b"?6h" } else { b"?6l" });
        // A saved cursor carries the designations and not the locking shift, because `DECSC` saves
        // the designations and a restore leaves whichever set was selected selected.
        self.designations(&cursor.charsets);
        self.rendition(cursor.rendition);
        match cursor.hyperlink.as_ref() {
            Some(uri) => self.open_link(uri),
            None => {
                if self.link.is_some() {
                    self.close_link();
                }
            }
        }
        let mut style = cursor.style.to_string().into_bytes();
        style.extend_from_slice(b" q");
        self.csi(&style);
        self.move_to(line, column);
        self.out.push(ESC);
        self.out.push(b'7');
        // Everything the save disturbed is put back, so the operations that follow describe the
        // screen rather than the pen this one happened to leave behind.
        self.rendition(restore_pen);
        match restore_link {
            Some(uri) => self.open_link(&uri),
            None => {
                if self.link.is_some() {
                    self.close_link();
                }
            }
        }
    }

    fn cursor(&mut self, cursor: CursorState) {
        // Everything the rows had to be painted without goes in here: the character sets the text
        // would have been drawn through, and the scroll region and origin mode that would have
        // moved every absolute address.
        if let Some(charsets) = self.charsets.take() {
            self.charsets(&charsets);
        }
        let margins = self.margins.take();
        if let Some(margins) = margins {
            self.install_margins(margins);
        }
        if self.origin_mode {
            // Enabling origin mode homes the cursor, so it happens before the cursor is placed and
            // the placement is then expressed in the origin's own coordinates.
            self.csi(b"?6h");
        }
        let mut style = cursor.style.to_string().into_bytes();
        style.extend_from_slice(b" q");
        self.csi(&style);
        let placed = match (self.line_of_row(cursor.row), self.column_of(cursor.col)) {
            (Some(line), Some(column)) => {
                // A pending wrap cannot be addressed: every cursor movement clears it. What sets it
                // is printing into the last column, so the cursor's own row is drawn again and the
                // cursor is left where that drawing ended.
                // A pending wrap is not reproducible here. Every cursor movement clears one, and
                // the only thing that sets one is printing into the last column — which would have
                // to happen after the pen, the character sets, the margins and the origin were
                // installed, and would then draw that cell through all of them. Drawing it before
                // they are installed does not work either, because installing the margins and the
                // origin moves the cursor. So it is reported rather than approximated: the next
                // character an application prints lands one cell along instead of wrapping.
                if cursor.pending_wrap {
                    self.carried.pending_wrap = true;
                }
                let (line, column) = if self.origin_mode {
                    let top = margins.map_or(0, |margins| margins.top);
                    let left = margins.map_or(0, |margins| margins.left);
                    (line.saturating_sub(top), column.saturating_sub(left))
                } else {
                    (line, column)
                };
                self.move_to(line, column);
                true
            }
            // The cursor is outside the window this terminal is looking at. Leaving it visible
            // wherever the last row happened to end would show a cursor that is not the session's.
            _ => false,
        };
        // Visibility comes last, so the person never watches a cursor travel across a repaint.
        self.csi(if cursor.visible && placed {
            b"?25h"
        } else {
            b"?25l"
        });
    }

    /// Paints the buffer that is not showing, by switching to it and back.
    ///
    /// `?47` switches without clearing either buffer, which `?1047` and `?1049` do not: entering
    /// through one of those would empty the buffer this is about to fill. Nothing else about the
    /// screen changes, and the active buffer is painted afterwards.
    fn paint_inactive_buffer(&mut self) {
        if self.inactive.is_empty() {
            return;
        }
        let rows = std::mem::take(&mut self.inactive);
        if self.scope == Scope::LiveScreen {
            // Outside this caller's authority. The rows are counted among what the restoration did
            // not carry, which is the same accounting a row a byte stream cannot paint gets: what
            // the screen holds and the caller was not shown is never silently dropped.
            self.carried.inactive_rows = self.carried.inactive_rows.saturating_add(rows.len());
            return;
        }
        let active = self.active;
        let window = self.viewport;
        // Into the other buffer. Switching resets the pen on the terminals this profile is written
        // against, so this writer's idea of what the terminal is in goes with it, in both
        // directions.
        self.csi(match active {
            ActiveBuffer::Primary => b"?47h",
            ActiveBuffer::Alternate => b"?47l",
        });
        self.active = match active {
            ActiveBuffer::Primary => ActiveBuffer::Alternate,
            ActiveBuffer::Alternate => ActiveBuffer::Primary,
        };
        self.pen = None;
        self.link = None;
        self.csi(b"H");
        self.csi(b"2J");
        // The other buffer's rows have their own stable identifiers, which are not the active
        // buffer's: anchoring them on the active window's top row would place them somewhere else
        // entirely, or nowhere at all.
        if let Some(first) = rows.first() {
            self.viewport = Viewport {
                top_row: first.stable_id,
                ..window
            };
        }
        for row in &rows {
            self.paint(row);
        }
        self.viewport = window;
        // And back, before anything of the active buffer is drawn.
        self.csi(match active {
            ActiveBuffer::Primary => b"?47l",
            ActiveBuffer::Alternate => b"?47h",
        });
        self.active = active;
        self.pen = None;
        self.link = None;
    }

    fn install_margins(&mut self, margins: Margins) {
        let mut vertical = (margins.top.saturating_add(1)).to_string().into_bytes();
        vertical.push(b';');
        vertical.extend_from_slice((margins.bottom.saturating_add(1)).to_string().as_bytes());
        vertical.push(b'r');
        self.csi(&vertical);
        // Left and right margins need the mode that enables them. A session that never set them
        // has them at the full width, and enabling the mode for that would change nothing while
        // leaving a mode set that the snapshot did not have set.
        if margins.left > 0 || margins.right.saturating_add(1) < self.viewport.cols {
            self.csi(b"?69h");
            let mut horizontal = (margins.left.saturating_add(1)).to_string().into_bytes();
            horizontal.push(b';');
            horizontal.extend_from_slice((margins.right.saturating_add(1)).to_string().as_bytes());
            horizontal.push(b's');
            self.csi(&horizontal);
        }
    }

    /// Returns the screen line one canonical row lands on, when the viewport shows it.
    fn line_of(&self, stable_id: i64) -> Option<u32> {
        let offset = stable_id.checked_sub(self.viewport.top_row)?;
        let line = u32::try_from(offset).ok()?;
        (line < self.viewport.rows).then_some(line)
    }

    /// Returns the screen line one row *of the visible page* lands on.
    ///
    /// A cursor row is counted from the top of the page rather than by stable identifier, which is
    /// what the engine's own cursor state carries.
    fn line_of_row(&self, row: u32) -> Option<u32> {
        (row < self.viewport.rows).then_some(row)
    }

    /// Returns the screen column one canonical column lands on, when the viewport shows it.
    fn column_of(&self, column: u32) -> Option<u32> {
        let offset = column.checked_sub(self.viewport.left_col)?;
        (offset < self.viewport.cols).then_some(offset)
    }

    fn move_to(&mut self, line: u32, column: u32) {
        let mut body = (line.saturating_add(1)).to_string().into_bytes();
        body.push(b';');
        body.extend_from_slice((column.saturating_add(1)).to_string().as_bytes());
        body.push(b'H');
        self.csi(&body);
    }

    fn move_to_column(&mut self, column: u32) {
        let mut body = (column.saturating_add(1)).to_string().into_bytes();
        body.push(b'G');
        self.csi(&body);
    }
}

/// Returns the SGR parameter one colour needs, or `None` for the session default.
fn colour_parameter(colour: Colour, base: u8, bright: u8, extended: u8) -> Option<String> {
    match colour {
        Colour::Default => None,
        Colour::Indexed(index) if index < 8 => Some((base + index).to_string()),
        Colour::Indexed(index) if index < 16 => Some((bright + (index - 8)).to_string()),
        Colour::Indexed(index) => Some(format!("{extended}:5:{index}")),
        Colour::Direct(rgb) => Some(format!("{extended}:2::{}:{}:{}", rgb.r, rgb.g, rgb.b)),
    }
}

/// Returns the `rgb:` specification an OSC colour command carries.
fn rgb_specification(colour: Rgb) -> Vec<u8> {
    format!("rgb:{:02x}/{:02x}/{:02x}", colour.r, colour.g, colour.b).into_bytes()
}

/// Returns as much of `text` as fits in `room` cells, and whether anything was left out.
///
/// The grid's own width model decides how many cells a grapheme occupies, so a wide character is
/// never split in half: a cell that would be cut leaves the character out instead of drawing a
/// half of it that the terminal would place somewhere of its own choosing.
fn clip_to_cells(text: &str, room: usize) -> (&str, bool) {
    if room == 0 {
        return ("", !text.is_empty());
    }
    if kr_term::unicode::cells_for(text) <= room {
        return (text, false);
    }
    let mut end = 0;
    let mut used = 0;
    for (offset, character) in text.char_indices() {
        let width = kr_term::unicode::cells_for(character.encode_utf8(&mut [0_u8; 4]));
        if used + width > room {
            break;
        }
        used += width;
        end = offset + character.len_utf8();
    }
    (&text[..end], true)
}

/// Returns the DEC designation byte of one character set the engine named.
///
/// The engine reports the grid library's own names. They are the three sets the kr-vt/1 profile
/// implements, and each has exactly one designation byte in the `SCS` sequences. A name this build
/// does not know is not guessed at: the designation is left alone and the run is drawn under
/// whatever the terminal already had, which is what the snapshot's own text already assumes.
const fn designation(name: &str) -> Option<u8> {
    match name.as_bytes() {
        b"Ascii" => Some(b'B'),
        b"Uk" => Some(b'A'),
        b"DecLineDrawing" => Some(b'0'),
        _ => None,
    }
}

/// Returns the bytes one side effect takes when its destination is a terminal.
///
/// The engine decodes a side effect rather than passing its bytes on, because deciding where it
/// goes means understanding what it asks for. Sending it to the one attachment that holds the
/// input lease therefore means writing it again, in the profile's own spelling rather than
/// whatever the application happened to use. Two consequences follow and both are wanted: a
/// sequence a terminal would not have understood becomes one it will, and nothing a terminal was
/// never meant to see can travel through here, because only the kinds below have a spelling at
/// all.
///
/// A clipboard *read* has none. The engine answers it, from the session rather than from whichever
/// terminal happens to be attached, so there is nothing to forward.
#[must_use]
pub fn side_effect(kind: &SideEffectKind) -> Option<Vec<u8>> {
    match kind {
        SideEffectKind::Bell => Some(vec![0x07]),
        SideEffectKind::ClipboardWrite { selection, content } => {
            let mut body = b";".to_vec();
            body.insert(0, selection_byte(*selection));
            body.extend_from_slice(base64(content).as_bytes());
            let mut out = Vec::new();
            osc_into(&mut out, b"52", &body);
            Some(out)
        }
        SideEffectKind::Notification {
            title,
            body,
            id,
            urgency,
            display,
        } => {
            // OSC 99 rather than OSC 777, because it is the spelling that carries everything the
            // application said: the identifier that groups and replaces a notification, the
            // urgency, and the condition under which it asked to be shown. OSC 777 has fields for
            // none of those, so converting to it would quietly turn a notification meant only for
            // an unfocused session into an unconditional one, and would leave an identifier to be
            // used as a title.
            let mut metadata: Vec<String> = Vec::new();
            if let Some(id) = id {
                metadata.push(format!("i={id}"));
            }
            metadata.push(format!(
                "u={}",
                match urgency {
                    NotificationUrgency::Low => 0,
                    NotificationUrgency::Normal => 1,
                    NotificationUrgency::Critical => 2,
                }
            ));
            metadata.push(
                match display {
                    NotificationDisplay::Always => "o=always",
                    NotificationDisplay::Unfocused => "o=unfocused",
                    NotificationDisplay::Invisible => "o=invisible",
                }
                .to_owned(),
            );
            let common = metadata.join(":");
            let mut out = Vec::new();
            // A title and a body are two payloads of one notification, and a payload longer than
            // the protocol's own bound is sent in parts. Only the very last one is marked complete,
            // because that is what tells the terminal the notification is whole.
            if let Some(title) = title {
                notification_payload(&mut out, &common, "title", title, false);
            }
            notification_payload(&mut out, &common, "body", body, true);
            Some(out)
        }
        SideEffectKind::Progress { progress } => {
            let (state, value) = match progress {
                Progress::None => (0_u8, 0_u8),
                Progress::Percent(percent) => (1, *percent),
                Progress::Error(percent) => (2, *percent),
                Progress::Indeterminate => (3, 0),
                Progress::Paused(percent) => (4, *percent),
            };
            let mut payload = b"4;".to_vec();
            payload.extend_from_slice(state.to_string().as_bytes());
            payload.push(b';');
            payload.extend_from_slice(value.to_string().as_bytes());
            let mut out = Vec::new();
            osc_into(&mut out, b"9", &payload);
            Some(out)
        }
        SideEffectKind::ClipboardRead { .. } => None,
    }
}

/// The largest payload one OSC 99 message carries.
const MAX_NOTIFICATION_PAYLOAD: usize = 2048;

/// Writes one notification payload, in as many messages as its length needs.
fn notification_payload(out: &mut Vec<u8>, common: &str, kind: &str, text: &str, last: bool) {
    // Split on character boundaries, not on bytes: half of a character is not a shorter payload,
    // it is an invalid one, and a terminal decoding it shows a replacement where the application
    // wrote a letter.
    let mut pieces: Vec<&str> = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = MAX_NOTIFICATION_PAYLOAD.min(rest.len());
        while end > 0 && !rest.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            // One character wider than the whole payload bound. Nothing can carry it.
            break;
        }
        pieces.push(&rest[..end]);
        rest = &rest[end..];
    }
    let mut chunks = pieces.into_iter().peekable();
    if chunks.peek().is_none() {
        let mut only = common.as_bytes().to_vec();
        only.extend_from_slice(format!(":p={kind}:d={};", u8::from(last)).as_bytes());
        osc_into(out, b"99", &only);
        return;
    }
    while let Some(chunk) = chunks.next() {
        let done = last && chunks.peek().is_none();
        let mut payload = common.as_bytes().to_vec();
        payload.extend_from_slice(format!(":p={kind}:d={};", u8::from(done)).as_bytes());
        payload.extend_from_slice(chunk.as_bytes());
        osc_into(out, b"99", &payload);
    }
}

/// Returns the byte that names one clipboard selection in an OSC 52 command.
const fn selection_byte(selection: ClipboardSelection) -> u8 {
    match selection {
        ClipboardSelection::Clipboard => b'c',
        ClipboardSelection::Primary => b'p',
    }
}

/// Writes one OSC command into a buffer.
fn osc_into(out: &mut Vec<u8>, number: &[u8], payload: &[u8]) {
    out.push(ESC);
    out.push(b']');
    out.extend_from_slice(number);
    out.push(b';');
    out.extend(payload.iter().copied().filter(|byte| *byte >= 0x20));
    out.extend_from_slice(ST);
}

/// Encodes bytes as standard base64, which is what an OSC 52 payload carries.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(char::from(ALPHABET[((first >> 18) & 0x3F) as usize]));
        out.push(char::from(ALPHABET[((first >> 12) & 0x3F) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[((first >> 6) & 0x3F) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[(first & 0x3F) as usize])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_term::budget::GridSize;
    use kr_term::snapshot::{KittyKeyboard, ModeEntry};
    use kr_term::title::{SavedTitle, TitleEntry};

    fn viewport(rows: u32, cols: u32) -> Viewport {
        Viewport {
            top_row: 0,
            rows,
            left_col: 0,
            cols,
        }
    }

    fn row(stable_id: i64, column: u32, text: &str) -> GridRow {
        GridRow {
            stable_id,
            soft_wrapped: false,
            truncated: false,
            runs: vec![Run {
                text: text.to_owned(),
                column,
                cells: u32::try_from(text.chars().count()).unwrap_or(0),
                rendition: Rendition::default(),
                hyperlink: None,
            }],
        }
    }

    #[test]
    fn a_restoration_carries_no_sequence_that_can_do_anything() {
        // Every command this writer emits is a rendering command. None of them rings a bell, asks
        // a question, writes a clipboard or starts anything, which is what makes a restoration
        // safe to send to a terminal that was not there when the history happened.
        let operations = vec![
            RestoreOp::ResetProjection { generation: 3 },
            RestoreOp::SetDimensions {
                size: GridSize::new(80, 24),
            },
            RestoreOp::SelectBuffer {
                buffer: ActiveBuffer::Primary,
            },
            RestoreOp::PaintRow {
                row: row(0, 0, "hello"),
            },
            RestoreOp::SetCursor {
                cursor: CursorState {
                    col: 5,
                    row: 0,
                    visible: true,
                    style: 1,
                    pending_wrap: false,
                },
            },
        ];
        let rendered = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let bytes = rendered.bytes;
        assert!(
            !bytes.windows(2).any(|pair| pair == b"\x1b]52"),
            "no clipboard write"
        );
        assert!(!bytes.contains(&0x07), "no bell");
        assert!(
            !bytes.windows(3).any(|triple| triple == b"\x1b[c"),
            "no query"
        );
        assert!(rendered.carried.complete());
    }

    #[test]
    fn a_row_is_drawn_from_an_empty_line() {
        let rendered = render(
            &[RestoreOp::PaintRow {
                row: row(2, 0, "text"),
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        // Line three, cleared, then the text.
        assert_eq!(
            rendered.bytes,
            b"\x1b[3;1H\x1b[K\x1b[1G\x1b[0mtext".to_vec()
        );
    }

    #[test]
    fn a_row_outside_the_viewport_is_not_drawn() {
        let rendered = render(
            &[RestoreOp::PaintRow {
                row: row(40, 0, "below"),
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert!(rendered.bytes.is_empty());
    }

    #[test]
    fn a_run_wider_than_the_window_is_clipped_rather_than_wrapped() {
        // A run drawn past the last column would wrap into the row below, and on the last row it
        // would scroll the screen this restoration is drawing.
        let rendered = render(
            &[RestoreOp::PaintRow {
                row: row(0, 0, "abcdefghij"),
            }],
            viewport(24, 4),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert!(text.ends_with("abcd"), "{text:?}");
        assert_eq!(rendered.carried.clipped_rows, 1);
    }

    #[test]
    fn a_wide_character_is_left_out_rather_than_half_drawn() {
        let rendered = render(
            &[RestoreOp::PaintRow {
                row: row(0, 0, "a\u{4e00}"),
            }],
            viewport(24, 2),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert!(text.ends_with('a'), "{text:?}");
        assert_eq!(rendered.carried.clipped_rows, 1);
    }

    #[test]
    fn a_cursor_outside_the_window_is_hidden_rather_than_left_somewhere_else() {
        let rendered = render(
            &[RestoreOp::SetCursor {
                cursor: CursorState {
                    col: 100,
                    row: 0,
                    visible: true,
                    style: 1,
                    pending_wrap: false,
                },
            }],
            viewport(24, 40),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert!(text.ends_with("\x1b[?25l"), "{text:?}");
    }

    #[test]
    fn rows_are_painted_before_the_margins_and_origin_that_would_move_them() {
        let operations = vec![
            RestoreOp::SetMode {
                entry: ModeEntry {
                    kind: kr_term::modes::ModeKind::Dec,
                    mode: 6,
                    enabled: true,
                },
            },
            RestoreOp::SetMargins {
                margins: Margins {
                    top: 5,
                    bottom: 20,
                    left: 0,
                    right: 79,
                },
            },
            RestoreOp::PaintRow {
                row: row(0, 0, "top"),
            },
            RestoreOp::SetCursor {
                cursor: CursorState {
                    col: 0,
                    row: 7,
                    visible: true,
                    style: 1,
                    pending_wrap: false,
                },
            },
        ];
        let rendered = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        let painted = text.find("top").expect("the row is painted");
        let region = text.find("\x1b[6;21r").expect("the scroll region is set");
        let origin = text.find("\x1b[?6h").expect("origin mode is set");
        assert!(painted < region, "the row is painted first: {text:?}");
        assert!(
            region < origin,
            "then the region, then origin mode: {text:?}"
        );
        // With origin mode in force, the cursor's absolute row 7 is row 2 of the region.
        assert!(text.contains("\x1b[3;1H"), "{text:?}");
    }

    #[test]
    fn a_cursor_save_is_not_treated_as_a_mode() {
        let rendered = render(
            &[RestoreOp::SetMode {
                entry: ModeEntry {
                    kind: kr_term::modes::ModeKind::Dec,
                    mode: 1048,
                    enabled: false,
                },
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert!(
            rendered.bytes.is_empty(),
            "restoring a saved cursor is not a mode to be left in"
        );
    }

    #[test]
    fn a_viewport_offsets_the_rows_and_columns_it_shows() {
        let looking_at = Viewport {
            top_row: 10,
            rows: 5,
            left_col: 4,
            cols: 10,
        };
        let rendered = render(
            &[RestoreOp::PaintRow {
                row: row(11, 6, "ab"),
            }],
            looking_at,
            Keyboard::Install,
            Scope::WholeScreen,
        );
        // Canonical row 11 is the second line shown; canonical column 6 is the third column shown.
        assert_eq!(rendered.bytes, b"\x1b[2;1H\x1b[K\x1b[3G\x1b[0mab".to_vec());
    }

    #[test]
    fn the_alternate_buffer_modes_are_not_set_twice() {
        let operations = vec![
            RestoreOp::SelectBuffer {
                buffer: ActiveBuffer::Alternate,
            },
            RestoreOp::SetMode {
                entry: ModeEntry {
                    kind: kr_term::modes::ModeKind::Dec,
                    mode: 1049,
                    enabled: true,
                },
            },
            RestoreOp::SetMode {
                entry: ModeEntry {
                    kind: kr_term::modes::ModeKind::Dec,
                    mode: 7,
                    enabled: true,
                },
            },
        ];
        let rendered = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert_eq!(rendered.bytes, b"\x1b[?1049h\x1b[?7h".to_vec());
    }

    #[test]
    fn a_rendition_is_emitted_whole_rather_than_as_a_difference() {
        let bold = Rendition {
            bold: true,
            foreground: Colour::Indexed(9),
            background: Colour::Direct(Rgb::new(1, 2, 3)),
            ..Rendition::default()
        };
        let rendered = render(
            &[RestoreOp::SetRendition { rendition: bold }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert_eq!(rendered.bytes, b"\x1b[0;1;91;48:2::1:2:3m".to_vec());
    }

    #[test]
    fn the_buffer_that_is_not_showing_is_painted_before_the_one_that_is() {
        // `?47` switches without clearing either buffer, so the screen this restoration is drawing
        // is never emptied to fill the other one.
        let operations = vec![
            RestoreOp::SelectBuffer {
                buffer: ActiveBuffer::Alternate,
            },
            RestoreOp::PaintInactiveRow {
                row: row(0, 0, "shell"),
            },
            RestoreOp::PaintRow {
                row: row(0, 0, "application"),
            },
        ];
        let rendered = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        let into_primary = text
            .find("\x1b[?47l")
            .expect("switches to the other buffer");
        let shell = text.find("shell").expect("the other buffer is painted");
        let back = text.rfind("\x1b[?47h").expect("switches back");
        let application = text
            .find("application")
            .expect("the active buffer is painted");
        assert!(into_primary < shell, "{text:?}");
        assert!(shell < back, "{text:?}");
        assert!(back < application, "{text:?}");
        assert_eq!(rendered.carried.inactive_rows, 0);
    }

    #[test]
    fn the_saved_cursor_of_the_other_buffer_is_reported_rather_than_approximated() {
        let operations = vec![
            RestoreOp::SelectBuffer {
                buffer: ActiveBuffer::Primary,
            },
            RestoreOp::SetSavedCursor {
                cursor: SavedCursor {
                    buffer: ActiveBuffer::Alternate,
                    col: 0,
                    row: 0,
                    pending_wrap: false,
                    rendition: Rendition::default(),
                    charsets: Designations {
                        g0: "Ascii".to_owned(),
                        g1: "Ascii".to_owned(),
                    },
                    origin_mode: false,
                    style: 1,
                    hyperlink: None,
                },
            },
        ];
        let rendered = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert_eq!(rendered.carried.other_saved_cursors, 1);
        assert!(!rendered.carried.complete());
    }

    #[test]
    fn a_pending_wrap_is_reported_rather_than_approximated() {
        // Every cursor movement clears a pending wrap and only printing into the last column sets
        // one, so a byte stream cannot put a terminal back into it without drawing a cell through
        // whatever pen, character set, margin and origin the restoration has installed. It is
        // counted instead, and the cost is that the next character lands one cell along.
        let operations = vec![
            RestoreOp::PaintRow {
                row: row(0, 0, "abcd"),
            },
            RestoreOp::SetCursor {
                cursor: CursorState {
                    col: 3,
                    row: 0,
                    visible: true,
                    style: 1,
                    pending_wrap: true,
                },
            },
        ];
        let rendered = render(
            &operations,
            viewport(24, 4),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert_eq!(text.matches("abcd").count(), 1, "{text:?}");
        assert!(rendered.carried.pending_wrap);
        assert!(!rendered.carried.complete());
    }

    #[test]
    fn a_live_screen_scope_is_not_drawn_the_buffer_that_is_not_showing() {
        let operations = [
            RestoreOp::SelectBuffer {
                buffer: ActiveBuffer::Alternate,
            },
            RestoreOp::PaintInactiveRow {
                row: row(0, 0, "secret"),
            },
            RestoreOp::PaintRow {
                row: row(0, 0, "shown"),
            },
        ];
        let whole = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let whole_text = String::from_utf8_lossy(&whole.bytes).into_owned();
        assert!(
            whole_text.contains("secret"),
            "the whole screen carries both buffers"
        );
        assert_eq!(whole.carried.inactive_rows, 0);

        let live = render(
            &operations,
            viewport(24, 80),
            Keyboard::Install,
            Scope::LiveScreen,
        );
        let live_text = String::from_utf8_lossy(&live.bytes).into_owned();
        assert!(
            !live_text.contains("secret"),
            "the live screen is the visible screen and nothing behind it: {live_text:?}"
        );
        assert!(live_text.contains("shown"), "and it is still drawn");
        assert_eq!(
            live.carried.inactive_rows, 1,
            "what it did not carry is counted rather than forgotten"
        );
    }

    #[test]
    fn the_title_stack_stays_virtual_rather_than_growing_the_terminals_own() {
        let rendered = render(
            &[RestoreOp::SetTitle {
                title: TitleEntry {
                    icon: "now".to_owned(),
                    window: "now".to_owned(),
                },
                stack: vec![SavedTitle {
                    icon: None,
                    window: Some("older".to_owned()),
                }],
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert!(
            !text.contains("older"),
            "the stack is not replayed: {text:?}"
        );
        assert!(
            !text.contains("22;0t"),
            "nothing is pushed onto the terminal's own stack: {text:?}"
        );
        assert!(text.ends_with("\x1b]2;now\x1b\\"));
        assert_eq!(rendered.carried.title_stack, 1, "and the loss is reported");
    }

    #[test]
    fn a_control_character_cannot_travel_back_through_a_row() {
        let mut dangerous = row(0, 0, "a\u{7}b");
        dangerous.runs[0].cells = 3;
        let rendered = render(
            &[RestoreOp::PaintRow { row: dangerous }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert!(!rendered.bytes.contains(&0x07));
    }

    #[test]
    fn the_link_the_application_has_open_is_left_open() {
        // The next character the application prints belongs to it, so closing it here would put
        // that text outside the link.
        let rendered = render(
            &[RestoreOp::SetHyperlink {
                uri: Some("https://example.invalid/".to_owned()),
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert_eq!(text, "\x1b]8;;https://example.invalid/\x1b\\");
    }

    #[test]
    fn a_link_opened_only_to_draw_a_run_is_closed_again() {
        let mut linked = row(0, 0, "text");
        linked.runs[0].hyperlink = Some("https://example.invalid/".to_owned());
        let rendered = render(
            &[
                RestoreOp::PaintRow { row: linked },
                RestoreOp::SetHyperlink { uri: None },
            ],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert!(text.ends_with("\x1b]8;;\x1b\\"), "{text:?}");
    }

    #[test]
    fn a_restoration_installs_the_flags_in_force_and_leaves_the_terminals_stack_alone() {
        let rendered = render(
            &[RestoreOp::SetKeyboard {
                keyboard: KeyboardSnapshot {
                    modify_other_keys: 2,
                    primary: KittyKeyboard {
                        flags: Some(5),
                        stack: vec![1, 3],
                    },
                    alternate: KittyKeyboard {
                        flags: None,
                        stack: Vec::new(),
                    },
                },
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        // The level and the flags in force, and nothing that touches the terminal's stack: the
        // entry the attachment saved its owner's negotiation in sits there, and a restoration that
        // emptied the stack or pushed onto it would take that away or bury it.
        assert_eq!(rendered.bytes, b"\x1b[>4;2m\x1b[=5;1u".to_vec());
        assert_eq!(
            rendered.carried.keyboard_stack, 2,
            "and the stack the session holds is counted as something this could not carry"
        );
        assert!(
            !rendered.carried.continues_the_stream(),
            "so the terminal is not handed the stream with a stack it would pop into \
             somebody else's state"
        );
    }

    #[test]
    fn a_terminal_that_was_asked_nothing_is_never_given_a_keyboard_protocol() {
        // `--no-probe` asks the terminal nothing, so nothing it has negotiated is known and nothing
        // could put back what installing a protocol would take away. The restoration leaves it
        // alone and counts what the session holds as something it could not carry.
        let keyboard = KeyboardSnapshot {
            modify_other_keys: 2,
            primary: KittyKeyboard {
                flags: Some(5),
                stack: vec![1],
            },
            alternate: KittyKeyboard {
                flags: None,
                stack: Vec::new(),
            },
        };
        let withheld = render(
            &[RestoreOp::SetKeyboard {
                keyboard: keyboard.clone(),
            }],
            viewport(24, 80),
            Keyboard::Withhold,
            Scope::WholeScreen,
        );
        assert!(
            withheld.bytes.is_empty(),
            "nothing about the keyboard is written: {:?}",
            String::from_utf8_lossy(&withheld.bytes)
        );
        assert!(
            withheld.carried.other_keyboard,
            "and what the session holds is counted as something this could not carry"
        );
        assert!(
            !withheld.carried.continues_the_stream(),
            "so the terminal is not handed the stream either"
        );

        // A terminal that said what it is gets the session's state, because the client read its own
        // before anything happened to it and can put that back exactly.
        let installed = render(
            &[RestoreOp::SetKeyboard { keyboard }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert_eq!(installed.bytes, b"\x1b[>4;2m\x1b[=5;1u".to_vec());
    }

    #[test]
    fn a_session_that_negotiated_no_keyboard_flags_installs_none_rather_than_nothing() {
        // A terminal a restoration reaches is not a terminal that started empty: whatever an
        // earlier application negotiated there is still in force. A session holding no flags has
        // to say so, or the application reads an encoding it never asked for.
        let rendered = render(
            &[RestoreOp::SetKeyboard {
                keyboard: KeyboardSnapshot {
                    modify_other_keys: 0,
                    primary: KittyKeyboard {
                        flags: None,
                        stack: Vec::new(),
                    },
                    alternate: KittyKeyboard {
                        flags: None,
                        stack: Vec::new(),
                    },
                },
            }],
            viewport(24, 80),
            Keyboard::Install,
            Scope::WholeScreen,
        );
        assert_eq!(rendered.bytes, b"\x1b[>4;0m\x1b[=0;1u".to_vec());
        assert_eq!(rendered.carried.keyboard_stack, 0);
    }
}
