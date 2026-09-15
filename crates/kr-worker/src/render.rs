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
//! that is showing, and the cursor.
//!
//! What a byte stream cannot carry is named here rather than approximated, and every one of them
//! is counted in [`Restoration::carried`] rather than left for a caller to discover:
//!
//! * **The buffer that is not showing, and its saved cursor and keyboard negotiation.** Painting
//!   or saving into it over a byte stream means switching to it and back, and a switch either
//!   clears the buffer it enters or moves the cursor of the one it leaves. A restoration must not
//!   disturb the screen it is restoring. A client that holds its own grid has no such constraint.
//! * **The virtual title stack.** Pushing it onto the terminal's own stack would grow that stack
//!   on every repaint and could evict what the person's own terminal had saved. Only the current
//!   title is set.
//! * **Soft-wrap markers.** A row this writer draws itself is a hard row as far as the terminal is
//!   concerned, so a line the application wrapped is copied as two lines rather than one.
//! * **The right-hand side of a row wider than the window.** A terminal narrower than the session
//!   is shown the part it has room for; nothing is reflowed and nothing wraps into the next row.
//!
//! Two things the pinned grid library does not expose are missing before this module sees them,
//! and are recorded in `kr_term::unicode::LIBRARY`: the pending-wrap flag, and the saved cursor of
//! either buffer. A restoration therefore cannot reproduce a pending wrap, and the saved cursor it
//! installs is whichever one the snapshot managed to carry.

use kr_term::grid::{Blink, Colour, GridRow, Rendition, Run, UnderlineStyle, VerticalPosition};
use kr_term::modes::ALTERNATE_BUFFER_MODES;
use kr_term::palette::Rgb;
use kr_term::sideeffect::{ClipboardSelection, Progress, SideEffectKind};
use kr_term::snapshot::{
    ActiveBuffer, Charsets, CursorState, KeyboardSnapshot, Margins, PaletteSnapshot, RestoreOp,
    SavedCursor, Viewport,
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

/// Renders a restoration for a terminal showing `viewport` of the canonical grid.
///
/// The viewport decides which canonical rows land on which screen lines and which columns are
/// shown, so a terminal smaller than the session sees the part it is looking at rather than a
/// wrapped approximation of the whole.
#[must_use]
pub fn render(operations: &[RestoreOp], viewport: Viewport) -> Restoration {
    let mut writer = Writer::new(viewport);
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
    /// The scroll region, held back until the rows have been painted.
    ///
    /// Every row is addressed absolutely, and an absolute address means something different once
    /// margins and origin mode are in force. The screen is therefore painted with neither, and both
    /// are installed afterwards together with the cursor, which is the only thing whose position
    /// they then apply to.
    margins: Option<Margins>,
    /// Whether the snapshot had origin mode set, held back for the same reason.
    origin_mode: bool,
    carried: Carried,
}

impl Writer {
    fn new(viewport: Viewport) -> Self {
        Self {
            out: Vec::new(),
            viewport,
            active: ActiveBuffer::Primary,
            pen: None,
            link: None,
            link_is_the_snapshots: false,
            margins: None,
            origin_mode: false,
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
            RestoreOp::SetCharsets { charsets } => self.charsets(charsets),
            // Held back until the rows are painted; see the field's own note.
            RestoreOp::SetMargins { margins } => self.margins = Some(*margins),
            RestoreOp::PaintInactiveRow { .. } => self.carried.inactive_rows += 1,
            RestoreOp::PaintRow { row } => self.paint(row),
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
        let mut body = b">".to_vec();
        body.extend_from_slice(b"4;");
        body.extend_from_slice(keyboard.modify_other_keys.to_string().as_bytes());
        body.push(b'm');
        self.csi(&body);
        // The stack belongs to the buffer that is showing. Emptying it first is what makes the
        // result the snapshot's stack rather than the snapshot's stack on top of whatever the
        // terminal already had.
        self.csi(b"<65535u");
        let (kitty, other) = match self.active {
            ActiveBuffer::Primary => (&keyboard.primary, &keyboard.alternate),
            ActiveBuffer::Alternate => (&keyboard.alternate, &keyboard.primary),
        };
        // The other buffer's negotiation has no sequence that installs it without switching to that
        // buffer, which a restoration must not do.
        if other.flags.is_some() || !other.stack.is_empty() {
            self.carried.other_keyboard = true;
        }
        // A push saves the flags that are *current* and installs its argument, so rebuilding a
        // stack means setting each value first and pushing the next one on top of it. Pushing the
        // stack's own values in order would save whatever happened to be current instead, and the
        // next pop would select an encoding the application never negotiated.
        let mut values = kitty.stack.clone();
        values.extend(kitty.flags);
        let mut values = values.into_iter();
        if let Some(first) = values.next() {
            let mut set = b"=".to_vec();
            set.extend_from_slice(first.to_string().as_bytes());
            set.extend_from_slice(b";1u");
            self.csi(&set);
        }
        for value in values {
            let mut push = b">".to_vec();
            push.extend_from_slice(value.to_string().as_bytes());
            push.push(b'u');
            self.csi(&push);
        }
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

    fn charsets(&mut self, charsets: &Charsets) {
        if let Some(designation) = designation(&charsets.g0) {
            self.out.push(ESC);
            self.out.push(b'(');
            self.out.push(designation);
        }
        if let Some(designation) = designation(&charsets.g1) {
            self.out.push(ESC);
            self.out.push(b')');
            self.out.push(designation);
        }
        self.out.push(if charsets.shift_out { 0x0E } else { 0x0F });
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
        self.charsets(&cursor.charsets);
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
        // The scroll region and origin mode go in here, after every row has been painted at an
        // absolute address and before the one position they apply to.
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
            title, body, id, ..
        } => {
            // OSC 777 is the spelling with the widest support, and it is the one kr-vt/1 names for
            // a notification a terminal is asked to raise. The identifier travels in the title
            // field's own separator position, where the sequence puts it.
            let mut payload = b"notify;".to_vec();
            let heading = title
                .as_deref()
                .unwrap_or_else(|| id.as_deref().unwrap_or(""));
            payload.extend_from_slice(heading.as_bytes());
            payload.push(b';');
            payload.extend_from_slice(body.as_bytes());
            let mut out = Vec::new();
            osc_into(&mut out, b"777", &payload);
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
                    pending_wrap: None,
                },
            },
        ];
        let rendered = render(&operations, viewport(24, 80));
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
                    pending_wrap: None,
                },
            }],
            viewport(24, 40),
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
                    pending_wrap: None,
                },
            },
        ];
        let rendered = render(&operations, viewport(24, 80));
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
        let rendered = render(&operations, viewport(24, 80));
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
        );
        assert_eq!(rendered.bytes, b"\x1b[0;1;91;48:2::1:2:3m".to_vec());
    }

    #[test]
    fn the_buffer_that_is_not_showing_is_reported_rather_than_approximated() {
        let operations = vec![
            RestoreOp::SelectBuffer {
                buffer: ActiveBuffer::Primary,
            },
            RestoreOp::PaintInactiveRow {
                row: row(0, 0, "hidden"),
            },
            RestoreOp::SetSavedCursor {
                cursor: SavedCursor {
                    buffer: ActiveBuffer::Alternate,
                    col: 0,
                    row: 0,
                    pending_wrap: false,
                    rendition: Rendition::default(),
                    charsets: Charsets {
                        g0: "B".to_owned(),
                        g1: "B".to_owned(),
                        shift_out: false,
                    },
                    origin_mode: false,
                    style: 1,
                    hyperlink: None,
                },
            },
        ];
        let rendered = render(&operations, viewport(24, 80));
        assert_eq!(rendered.carried.inactive_rows, 1);
        assert_eq!(rendered.carried.other_saved_cursors, 1);
        assert!(!rendered.carried.complete());
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
        let rendered = render(&[RestoreOp::PaintRow { row: dangerous }], viewport(24, 80));
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
        );
        let text = String::from_utf8_lossy(&rendered.bytes).into_owned();
        assert!(text.ends_with("\x1b]8;;\x1b\\"), "{text:?}");
    }

    #[test]
    fn the_keyboard_stack_is_emptied_before_it_is_rebuilt() {
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
        );
        // A push saves what is current, so the stack is rebuilt by setting each value and pushing
        // the next on top of it: set 1, push 3 (saving 1), push 5 (saving 3). The result is the
        // stack [1, 3] with 5 in force.
        assert_eq!(
            rendered.bytes,
            b"\x1b[>4;2m\x1b[<65535u\x1b[=1;1u\x1b[>3u\x1b[>5u".to_vec()
        );
    }
}
