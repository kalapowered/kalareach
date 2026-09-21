//! The projection wire protocol: snapshots, row pages, deltas and explicit resets.
//!
//! A projected attachment does not receive the application's bytes. It receives the canonical grid
//! as state: one snapshot of everything a screen is, then the rows in bounded pages, then one
//! bounded update per batch of output. The renderer lives in the client, which is what lets a
//! terminal of another size, a mobile screen and a desktop window each draw the same session
//! without any of them being sent bytes that assume it is the session's size.
//!
//! # Why the state is carried rather than the bytes
//!
//! Replaying bytes replays what they did. A terminal's history is full of things that *were*
//! events: a bell, a clipboard write, a notification, a query. Everything in this module is
//! presentation state, and nothing in it can ring, copy, notify, download, launch or ask anything.
//! Installing a snapshot therefore has no side effect, however the history was built.
//!
//! # The three rules that shape the types
//!
//! 1. **Every update names the base it continues from.** A [`ProjectionDelta`] carries
//!    `base_cursor` and `projection_generation`, and a client that holds neither of them discards
//!    what it has and installs a fresh snapshot. A cursor alone is not enough: a projection reset
//!    can happen without a byte arriving, so the same cursor can name two different screens.
//! 2. **Nothing is unbounded.** A snapshot's rows arrive in pages bounded by
//!    [`MAX_PROJECTION_PAGE_ROWS`] and [`MAX_PROJECTION_PAGE_BYTES`], the same two limits section 8
//!    puts on a history page. A page that had to leave something out says so, so a client never
//!    mistakes a truncation for the screen.
//! 3. **A reset is explicit.** A buffer switch, a geometry change and an eviction each replace the
//!    screen rather than changing it, and each sends [`ProjectionReset`] instead of a delta that a
//!    client could apply to the wrong grid.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::scalars::{Nullable, U64};
use crate::session::Dimensions;

/// Rows one projection page may carry.
///
/// The same bound section 8 puts on a terminal history page. A canonical grid may be 1,024 rows
/// and both buffers are carried, so a snapshot of a large session is several pages whatever the
/// byte bound says.
pub const MAX_PROJECTION_PAGE_ROWS: u64 = 1_000;

/// Bytes of encoded content one projection page may carry.
pub const MAX_PROJECTION_PAGE_BYTES: u64 = 1024 * 1024;

/// Which screen buffer something belongs to.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedBuffer {
    /// The primary buffer, which has the scrollback.
    Primary,
    /// The alternate buffer, which has none.
    Alternate,
}

impl ProjectedBuffer {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Alternate => "alternate",
        }
    }
}

/// A direct colour.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Rgb {
    /// Red.
    pub red: u8,
    /// Green.
    pub green: u8,
    /// Blue.
    pub blue: u8,
}

/// One cell colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CellColour {
    /// The session's own default, which a client resolves against the palette it was given.
    Default,
    /// A palette index.
    Indexed(u8),
    /// A direct colour.
    Direct(Rgb),
}

/// How a run of cells is underlined.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CellUnderline {
    /// Not underlined.
    None,
    /// One line.
    Single,
    /// Two lines.
    Double,
    /// A curly line.
    Curly,
    /// A dotted line.
    Dotted,
    /// A dashed line.
    Dashed,
}

/// Whether and how a run of cells blinks.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CellBlink {
    /// Not blinking.
    None,
    /// The slow rate.
    Slow,
    /// The rapid rate.
    Rapid,
}

/// Where a run of cells sits against the baseline.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CellVerticalAlign {
    /// On the baseline.
    Baseline,
    /// Raised.
    Superscript,
    /// Lowered.
    Subscript,
}

/// The graphic rendition of a run of cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CellRendition {
    /// The text colour.
    pub foreground: CellColour,
    /// The cell colour.
    pub background: CellColour,
    /// The underline colour, where it differs from the text.
    pub underline_colour: CellColour,
    /// The underline style.
    pub underline: CellUnderline,
    /// The blink rate.
    pub blink: CellBlink,
    /// The position against the baseline.
    pub vertical_align: CellVerticalAlign,
    /// Bold.
    pub bold: bool,
    /// Faint.
    pub faint: bool,
    /// Italic.
    pub italic: bool,
    /// Reverse video.
    pub reverse: bool,
    /// Invisible.
    pub invisible: bool,
    /// Struck through.
    pub strikethrough: bool,
    /// Overlined.
    pub overline: bool,
}

impl CellRendition {
    /// The rendition a terminal starts in.
    pub const PLAIN: Self = Self {
        foreground: CellColour::Default,
        background: CellColour::Default,
        underline_colour: CellColour::Default,
        underline: CellUnderline::None,
        blink: CellBlink::None,
        vertical_align: CellVerticalAlign::Baseline,
        bold: false,
        faint: false,
        italic: false,
        reverse: false,
        invisible: false,
        strikethrough: false,
        overline: false,
    };
}

/// One run of cells that share a rendition and a hyperlink.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CellRun {
    /// The canonical column of the first cell, zero-based.
    pub column: U64,
    /// How many cells the run occupies, counting a wide cell as two.
    ///
    /// A client draws from `column` and advances by this, so a destination whose own width model
    /// disagrees with the session's is corrected at the next run rather than shifting everything
    /// after it.
    pub cells: U64,
    /// The text.
    pub text: String,
    /// The rendition.
    pub rendition: CellRendition,
    /// The hyperlink this run is inside, as inert metadata.
    pub hyperlink: Nullable<String>,
}

/// One row of the canonical grid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectedRow {
    /// The stable identifier, which survives scrollback eviction and names the same row in every
    /// later update.
    pub row: U64,
    /// Whether the row ends in a soft wrap rather than a hard line break.
    ///
    /// A selection that copies two soft-wrapped rows copies one logical line, which is why the
    /// marker travels with the row instead of being inferred from its length.
    pub soft_wrapped: bool,
    /// Whether runs were dropped to keep the row inside a page's byte bound.
    ///
    /// The degradation is explicit: a client shows what it was given and knows it is not all of
    /// the row, rather than drawing a short row as though the application had written one.
    pub truncated: bool,
    /// The runs, left to right.
    pub runs: Vec<CellRun>,
}

/// The cursor, as a projection carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectedCursor {
    /// The canonical column, zero-based.
    pub column: U64,
    /// The row within the visible page, zero-based.
    pub row: U64,
    /// Whether the cursor is shown.
    pub visible: bool,
    /// The cursor-style number.
    pub style: U64,
    /// Whether the next printable character wraps before it is placed.
    ///
    /// The same coordinates mean different things with and without it, so a renderer that left it
    /// out would put the next character in the wrong cell.
    pub pending_wrap: bool,
}

/// The part of the canonical grid one client is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectedViewport {
    /// The stable identifier of the first row shown.
    pub top_row: U64,
    /// The stable identifier of the live screen's first row.
    ///
    /// The two are the same for a window on the live screen and different for one above it. Both
    /// are needed because they are the origins of two different things: the rows a client draws
    /// are named by [`Self::top_row`], and the cursor's own row is a line of the live screen. A
    /// client with only one of them would put the cursor on a line of its history.
    pub screen_top_row: U64,
    /// How many rows are shown.
    pub rows: U64,
    /// The first canonical column shown, for a display narrower than the grid.
    pub left_column: U64,
    /// How many columns are shown.
    pub columns: U64,
}

/// Which spelling a tracked mode has.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedModeKind {
    /// An ANSI mode, set with `CSI h` and reset with `CSI l`.
    Ansi,
    /// A DEC private mode, set with `CSI ? h` and reset with `CSI ? l`.
    Dec,
}

/// One tracked mode and its value.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProjectedMode {
    /// Which spelling.
    pub kind: ProjectedModeKind,
    /// The mode number.
    pub mode: U64,
    /// Whether it is set.
    pub enabled: bool,
}

/// One buffer's Kitty keyboard negotiation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KittyKeyboardState {
    /// The flags in force, when the protocol is in use.
    pub flags: Nullable<U64>,
    /// The flag stack, oldest first.
    pub stack: Vec<U64>,
}

/// The keyboard negotiation an input encoder has to reproduce.
///
/// Each buffer has its own stack, so a full-screen application's negotiation cannot leak into the
/// shell's when it exits. A client that knew only the active one would send the wrong encoding the
/// moment the application quit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectedKeyboard {
    /// The `modifyOtherKeys` level.
    pub modify_other_keys: U64,
    /// The primary buffer's negotiation.
    pub primary: KittyKeyboardState,
    /// The alternate buffer's negotiation.
    pub alternate: KittyKeyboardState,
}

/// Where the session's palette came from.
///
/// Provenance travels with the palette because succession must not change it. A second attachment
/// with different colours is shown the session's palette, not its own, and the source says which
/// one that is.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PaletteProvenance {
    /// The profile's own default palette.
    ProfileDefault,
    /// A client's stated foreground and background, shared during the bounded probe.
    ClientPreference,
    /// The light preset, selected for a no-probe or invisible creation.
    LightPreset,
    /// The dark preset, selected for a no-probe or invisible creation.
    DarkPreset,
    /// An authorised, explicit palette change made after creation.
    ExplicitChange,
}

impl PaletteProvenance {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileDefault => "profile_default",
            Self::ClientPreference => "client_preference",
            Self::LightPreset => "light_preset",
            Self::DarkPreset => "dark_preset",
            Self::ExplicitChange => "explicit_change",
        }
    }
}

/// One indexed colour that differs from the profile default.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PaletteOverride {
    /// The palette index.
    pub index: u8,
    /// The colour.
    pub colour: Rgb,
}

/// The session's canonical palette and where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaletteState {
    /// Where this palette came from.
    pub source: PaletteProvenance,
    /// The default foreground.
    pub foreground: Rgb,
    /// The default background.
    pub background: Rgb,
    /// The cursor colour.
    pub cursor: Rgb,
    /// The pointer foreground.
    pub pointer_foreground: Rgb,
    /// The pointer background.
    pub pointer_background: Rgb,
    /// The selection background.
    pub selection_background: Rgb,
    /// The selection foreground.
    pub selection_foreground: Rgb,
    /// The indexed colours that differ from the profile default.
    pub overrides: Vec<PaletteOverride>,
}

/// The character sets a saved cursor carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CharsetDesignations {
    /// The set designated as G0.
    pub g0: String,
    /// The set designated as G1.
    pub g1: String,
}

/// The designated character sets and the locking shift.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CharsetState {
    /// The set designated as G0.
    pub g0: String,
    /// The set designated as G1.
    pub g1: String,
    /// Whether the shift-out set is selected.
    pub shift_out: bool,
}

/// The scroll region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarginState {
    /// The top row, zero-based and inclusive.
    pub top: U64,
    /// The bottom row, zero-based and inclusive.
    pub bottom: U64,
    /// The left column, zero-based and inclusive.
    pub left: U64,
    /// The right column, zero-based and inclusive.
    pub right: U64,
}

/// A cursor an application saved, with the pen it saved alongside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedCursorState {
    /// Which buffer saved it.
    pub buffer: ProjectedBuffer,
    /// The column, zero-based.
    pub column: U64,
    /// The row, zero-based.
    pub row: U64,
    /// Whether the saved cursor had a pending wrap.
    pub pending_wrap: bool,
    /// The rendition saved with it.
    pub rendition: CellRendition,
    /// The character sets designated when it was saved.
    pub charsets: CharsetDesignations,
    /// Whether origin mode was set when it was saved.
    pub origin_mode: bool,
    /// The cursor-style number saved with it.
    pub style: U64,
    /// The hyperlink that was open when it was saved.
    pub hyperlink: Nullable<String>,
}

/// The current titles.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectedTitle {
    /// The icon title.
    pub icon: String,
    /// The window title.
    pub window: String,
}

/// One entry of the virtual title stack.
///
/// A push saves only the titles it names, so each field is either a title that was saved or
/// nothing at all. The two are different: a pop leaves the current title alone where nothing was
/// saved for it, and a client that flattened the distinction would show the wrong title after one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedTitleEntry {
    /// The icon title, when this entry saved one.
    pub icon: Nullable<String>,
    /// The window title, when this entry saved one.
    pub window: Nullable<String>,
}

/// A hyperlink over a range of cells.
///
/// It is inert metadata. A reconnection restores it so a later click still works; nothing here
/// activates anything, and a scheme that would launch an external application needs the client's
/// own policy before anything happens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HyperlinkRange {
    /// The stable row identifier.
    pub row: U64,
    /// The first column, zero-based.
    pub start_column: U64,
    /// One past the last column.
    pub end_column: U64,
    /// The target.
    pub uri: String,
}

/// The hyperlink the next character printed belongs to, once it has changed.
///
/// A null target is an open link that closed. Without the distinction a client could not tell a
/// link that closed from one that was never mentioned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HyperlinkChange {
    /// The target, or null when no link is open.
    pub uri: Nullable<String>,
}

/// Everything a screen is, apart from its rows.
///
/// The rows follow in [`ProjectionRowPage`]s, because a canonical grid of 2,048 columns by 1,024
/// rows in two buffers is not one message. A client installs the state here, paints the pages as
/// they arrive, and applies deltas from `output_cursor` once the last page has landed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSnapshot {
    /// The generation this screen belongs to. Every later update names it.
    pub projection_generation: U64,
    /// The monotonic output cursor this snapshot describes. Updates resume from here.
    pub output_cursor: U64,
    /// Which buffer is active.
    pub active_buffer: ProjectedBuffer,
    /// The canonical dimensions.
    pub dimensions: Dimensions,
    /// The window this client is showing.
    pub viewport: ProjectedViewport,
    /// The cursor.
    pub cursor: ProjectedCursor,
    /// The cursor each buffer has saved.
    pub saved_cursors: Vec<SavedCursorState>,
    /// The scroll region.
    pub margins: MarginState,
    /// The pen the next character would be drawn with.
    pub rendition: CellRendition,
    /// The columns carrying a tab stop.
    pub tab_stops: Vec<U64>,
    /// The designated character sets.
    pub charsets: CharsetState,
    /// Every tracked mode.
    pub modes: Vec<ProjectedMode>,
    /// Whether the keypad is in application mode.
    pub keypad_application: bool,
    /// The keyboard negotiation an input encoder has to reproduce.
    pub keyboard: ProjectedKeyboard,
    /// The current titles.
    pub title: ProjectedTitle,
    /// The virtual title stack, oldest first.
    pub title_stack: Vec<SavedTitleEntry>,
    /// The hyperlink the next character printed belongs to.
    pub hyperlink: Nullable<String>,
    /// The canonical palette and its provenance.
    pub palette: PaletteState,
    /// The oldest row still retained anywhere.
    pub oldest_retained_row: U64,
    /// Whether rows below `oldest_retained_row` have been evicted.
    pub evicted: bool,
    /// Whether the session has had to shorten content to stay inside a resident-state bound.
    ///
    /// Section 8 requires truncation to have an explicit projection degradation, and a client in
    /// projected mode cannot see it any other way: a cell whose combining marks were dropped at
    /// the per-cell bound, a title cut to its limit and a hyperlink the link table refused all
    /// arrive looking like content the application wrote. This says they do not.
    pub degraded: bool,
}

/// One page of rows belonging to one buffer of one snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRowPage {
    /// The generation these rows belong to.
    pub projection_generation: U64,
    /// The cursor of the snapshot these rows complete.
    pub output_cursor: U64,
    /// Which buffer they belong to.
    pub buffer: ProjectedBuffer,
    /// The rows, in stable-identifier order.
    pub rows: Vec<ProjectedRow>,
    /// The oldest row still retained anywhere.
    pub oldest_retained_row: U64,
    /// Whether rows below `oldest_retained_row` have been evicted.
    pub evicted: bool,
    /// Whether more pages of this snapshot follow.
    ///
    /// A client that has not seen a page with this clear does not yet hold the whole screen, and
    /// section 8 forbids mixing live output with an incomplete repaint.
    pub more: bool,
}

/// A bounded update against a known base.
///
/// This is what a projected attachment receives per batch of output: the rows that changed and the
/// state that changed with them, never the whole screen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionDelta {
    /// The cursor this update continues from. A client holding another one asks for a snapshot.
    pub base_cursor: U64,
    /// The cursor after it.
    pub next_cursor: U64,
    /// The generation it belongs to.
    pub projection_generation: U64,
    /// Which buffer the rows belong to.
    pub buffer: ProjectedBuffer,
    /// The window this client is showing, which a scroll moves without changing any row.
    pub viewport: ProjectedViewport,
    /// The rows that changed, by stable identifier. A row not named here is unchanged.
    pub rows: Vec<ProjectedRow>,
    /// The cursor after the update.
    pub cursor: ProjectedCursor,
    /// The modes that changed since the base.
    pub modes: Vec<ProjectedMode>,
    /// The scroll region, when it changed.
    pub margins: Nullable<MarginState>,
    /// The pen, when it changed.
    pub rendition: Nullable<CellRendition>,
    /// The tab stops, when they changed.
    pub tab_stops: Nullable<Vec<U64>>,
    /// The designated character sets, when they changed.
    pub charsets: Nullable<CharsetState>,
    /// The hyperlink ranges of the rows carried here.
    pub hyperlinks: Vec<HyperlinkRange>,
    /// The open hyperlink, when it changed.
    pub hyperlink: Nullable<HyperlinkChange>,
    /// The titles, when they changed.
    pub title: Nullable<ProjectedTitle>,
    /// The virtual title stack, when the titles changed.
    pub title_stack: Nullable<Vec<SavedTitleEntry>>,
    /// The keyboard negotiation, when it changed.
    pub keyboard: Nullable<ProjectedKeyboard>,
    /// The palette, when an authorised explicit change moved it.
    pub palette: Nullable<PaletteState>,
    /// The canonical dimensions, when they changed.
    pub dimensions: Nullable<Dimensions>,
    /// The saved cursors, when one was saved or restored.
    pub saved_cursors: Nullable<Vec<SavedCursorState>>,
    /// The oldest row still retained anywhere.
    pub oldest_retained_row: U64,
    /// Whether rows below `oldest_retained_row` have been evicted.
    pub evicted: bool,
    /// Whether the session has had to shorten content to stay inside a resident-state bound.
    pub degraded: bool,
}

/// Why a projection was reset.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionResetReason {
    /// The attachment has just joined, or has just been moved into projected mode.
    Attached,
    /// The screen buffer changed, which replaces the grid rather than changing it.
    BufferSwitch,
    /// The canonical geometry changed, which reflows every row.
    Geometry,
    /// The client's base cursor is outside the bounded replay window.
    ReplayGap,
    /// What changed is larger than one bounded update, so the screen is sent again.
    ///
    /// An update carries the rows that changed. When that is most of the grid it is not an update,
    /// and sending it as one would mean one message larger than a page bound; the snapshot pages
    /// instead.
    Repaint,
    /// Retained rows the client was holding have been evicted.
    HistoryEvicted,
}

impl ProjectionResetReason {
    /// Every reason, which a caller measuring what a reset can cost walks.
    pub const ALL: &'static [Self] = &[
        Self::Attached,
        Self::BufferSwitch,
        Self::Geometry,
        Self::ReplayGap,
        Self::Repaint,
        Self::HistoryEvicted,
    ];

    /// The reason whose wire string is longest, which is what a reset costs at most.
    #[must_use]
    pub fn longest() -> Self {
        Self::ALL
            .iter()
            .copied()
            .max_by_key(|reason| reason.as_str().len())
            .unwrap_or(Self::Attached)
    }

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::BufferSwitch => "buffer_switch",
            Self::Geometry => "geometry",
            Self::ReplayGap => "replay_gap",
            Self::Repaint => "repaint",
            Self::HistoryEvicted => "history_evicted",
        }
    }
}

/// Discard whatever is being shown; a snapshot follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReset {
    /// The generation the client is now on.
    pub projection_generation: U64,
    /// The cursor the reset happened at.
    pub cursor: U64,
    /// Why.
    pub reason: ProjectionResetReason,
}

/// The event type of a projection reset.
pub const PROJECTION_RESET_EVENT: &str = "session.projection.reset";

/// The event type of a projection snapshot.
pub const PROJECTION_SNAPSHOT_EVENT: &str = "session.projection.snapshot";

/// The event type of a projection row page.
pub const PROJECTION_ROWS_EVENT: &str = "session.projection.rows";

/// The event type of a projection delta.
pub const PROJECTION_DELTA_EVENT: &str = "session.projection.delta";

/// The event type one settled agent resource is published under.
pub const AGENT_RESOURCE_EVENT: &str = "session.agent.resource";

/// What class of content an agent resource holds, as section 24 classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentResourceContentClass {
    /// Operation metadata: identifiers, revisions, states, digests and counts.
    Metadata,
    /// Terminal output bytes, as the application produced them.
    TerminalContent,
    /// Text a person wrote or an agent asked for.
    AuthoredContent,
    /// An untrusted notice an application asked the terminal to deliver.
    ApplicationNotice,
    /// Key material.
    Secret,
}

impl AgentResourceContentClass {
    /// Returns the stable string for this content class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::TerminalContent => "terminal",
            Self::AuthoredContent => "authored",
            Self::ApplicationNotice => "notice",
            Self::Secret => "secret",
        }
    }
}

/// Which of the broker's paths decided an agent resource transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentResourceCause {
    /// The resource was recorded as it arrived.
    Recorded,
    /// A decoder's verified interpretation made it answerable.
    Interpreted,
    /// A rich client claimed it, or gave the claim back.
    RichClaim,
    /// An answer left this host for it.
    Dispatched,
    /// A rich client's answer settled it.
    RichAnswer,
    /// The native terminal's own answer settled it.
    NativeAnswer,
    /// The upstream answered or withdrew its own request.
    Upstream,
    /// A reconciliation after a reconnection or a recovery settled it.
    Reconciliation,
}

impl AgentResourceCause {
    /// Returns the stable string for this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Interpreted => "interpreted",
            Self::RichClaim => "rich_claim",
            Self::Dispatched => "dispatched",
            Self::RichAnswer => "rich_answer",
            Self::NativeAnswer => "native_answer",
            Self::Upstream => "upstream",
            Self::Reconciliation => "reconciliation",
        }
    }
}

/// One committed broker transition, as an attached view is told about it.
///
/// Section 12 fans resolutions out to every authorised observer and section 24 makes the
/// transition and its event one record. This is the shape that record takes on the way to a view:
/// what changed, what it became, and where the change sits in the broker's own ordered stream, so
/// a view that missed one can see that it did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentResourceEvent {
    /// The session the instance belongs to.
    pub session_id: crate::ids::SessionId,
    /// The instance whose resource changed.
    pub application_instance_id: crate::ids::ApplicationInstanceId,
    /// The resource.
    pub resource_id: crate::ids::PendingResourceId,
    /// What it became.
    pub state: crate::gateway::PendingState,
    /// What class of content the resource holds, which is section 24's content classification.
    pub content: AgentResourceContentClass,
    /// Whether its history is durable or lived through an evidence gap.
    pub durability: crate::session::Durability,
    /// Which of the broker's paths decided it.
    pub cause: AgentResourceCause,
    /// The actor whose action caused it, where one did.
    pub actor_id: Nullable<crate::ids::ActorId>,
    /// The upstream request this resource belongs to, which is the root of its causal chain.
    pub causal_root: String,
    /// The binding revision in force when it changed.
    pub binding_revision: crate::ids::AgentBindingRevision,
    /// Which run of the broker's stream this event's position belongs to.
    ///
    /// Positions are unique inside one generation and are not comparable across two: a transition
    /// announced while the journal was faulted spends a position that was never written down, and
    /// the next run of the host numbers from what it did write. A view compares sequences only
    /// with those of the same generation, and treats a change of generation as the instruction to
    /// discard what it held and install a fresh [`AgentResourceSnapshot`].
    pub stream_generation: U64,
    /// This event's position in the broker's ordered stream of transitions.
    pub sequence: U64,
    /// The event itself, which never changes and never repeats.
    pub event_id: crate::scalars::Uuid,
    /// The previous event about this same resource, where there is one.
    pub parent_sequence: Nullable<U64>,
}

/// One page of the agent resources a view installs when it starts or resynchronises.
///
/// A view is told what changed, one transition at a time, and a view whose queue overflowed was
/// told to discard what it held. Neither of those is a way back to the truth on its own: the
/// events it missed are gone from its queue, and what it still holds is a partial history. This is
/// the way back. It is taken at one position of the broker's stream, and together its pages hold
/// every resource the broker is still arbitrating at that position.
///
/// # Why it is paged
///
/// How many resources a host arbitrates is decided by how long the session ran and how much its
/// upstreams asked of it, so a state carried whole is a state that eventually does not fit the
/// control frame it has to travel in. A subscription that cannot deliver the state cannot restore
/// the view, which is exactly the failure the state exists to prevent. So a page is bounded by
/// what one frame carries, `continue_after` names where the next page starts, and
/// [`AgentResourceSnapshotContinuation`] asks for it.
///
/// # What makes the pages one state
///
/// A page names the run it belongs to, the position it is current at and the revision of the
/// resources it describes, and every page of one snapshot names the same three. The host changes
/// `revision` whenever it changes what a page would carry, so it can refuse a continuation of a
/// state that no longer exists rather than answer with pages that were never true together: a
/// client is told to start again instead of assembling a half of one state onto a half of
/// another.
///
/// # How it meets the events
///
/// The two fit together at exactly one place. Everything this describes happened at or before
/// `cursor`, and every transition committed after this snapshot was taken carries a higher
/// position. What arrives afterwards is not ordered by that, though: an event committed earlier
/// can still be in flight and reach the view after this does. So a view installs the resources
/// here and then, within the same `stream_generation`, applies the events whose `sequence` is
/// above `cursor` and discards the rest. That gives it the whole stream with nothing counted
/// twice. An event of another generation belongs to another run of the host and is not comparable
/// with this position at all: the view installs a fresh snapshot for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentResourceSnapshot {
    /// Which run of the broker's stream `cursor` belongs to.
    pub stream_generation: U64,
    /// The position this state is current at.
    pub cursor: U64,
    /// Which revision of the host's resources this page describes.
    ///
    /// It changes whenever the host changes what a page would carry, and it is what a
    /// continuation is checked against, so two pages that name the same revision describe one
    /// state and never two.
    pub revision: U64,
    /// The resources this page carries, in identifier order.
    pub resources: Vec<crate::gateway::PendingResource>,
    /// The resource this page ends at, when the state continues past it.
    ///
    /// Null says the snapshot is complete. Otherwise the rest is asked for with an
    /// [`AgentResourceSnapshotContinuation`] naming this identifier.
    pub continue_after: Nullable<crate::ids::PendingResourceId>,
}

/// Where a paged agent-resource snapshot continues, and which state it continues.
///
/// It carries the whole identity of the page it follows rather than a position alone, because a
/// position alone cannot tell a continuation of one state from a continuation of the next one. A
/// host that no longer holds the named state answers `RESYNC_REQUIRED`, and the client takes a
/// fresh snapshot from the first page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentResourceSnapshotContinuation {
    /// The `stream_generation` of the page this continues.
    pub stream_generation: U64,
    /// The `cursor` of the page this continues.
    pub cursor: U64,
    /// The `revision` of the page this continues.
    pub revision: U64,
    /// The `continue_after` of the page this continues.
    pub after_resource_id: crate::ids::PendingResourceId,
}

/// One thing a projected attachment is sent, in the order the session produced it.
///
/// The order is the contract: a reset, then a snapshot, then its pages, then deltas from the
/// snapshot's cursor. Nothing in it carries a side effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionEvent {
    /// Discard and wait for a snapshot.
    Reset(ProjectionReset),
    /// The state of a screen, without its rows.
    Snapshot(Box<ProjectionSnapshot>),
    /// One page of a snapshot's rows.
    Rows(ProjectionRowPage),
    /// A bounded update.
    Delta(Box<ProjectionDelta>),
}

impl ProjectionEvent {
    /// Returns the event type this is published under.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Reset(_) => PROJECTION_RESET_EVENT,
            Self::Snapshot(_) => PROJECTION_SNAPSHOT_EVENT,
            Self::Rows(_) => PROJECTION_ROWS_EVENT,
            Self::Delta(_) => PROJECTION_DELTA_EVENT,
        }
    }

    /// Returns the cursor this event describes.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        match self {
            Self::Reset(reset) => reset.cursor.get(),
            Self::Snapshot(snapshot) => snapshot.output_cursor.get(),
            Self::Rows(page) => page.output_cursor.get(),
            Self::Delta(delta) => delta.next_cursor.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_projection_page_carries_the_section_eight_bounds() {
        assert_eq!(MAX_PROJECTION_PAGE_ROWS, 1_000);
        assert_eq!(MAX_PROJECTION_PAGE_BYTES, 1024 * 1024);
    }

    #[test]
    fn every_projection_event_has_its_own_type() {
        let mut types = [
            PROJECTION_RESET_EVENT,
            PROJECTION_SNAPSHOT_EVENT,
            PROJECTION_ROWS_EVENT,
            PROJECTION_DELTA_EVENT,
        ];
        types.sort_unstable();
        let count = types.len();
        let mut unique = types.to_vec();
        unique.dedup();
        assert_eq!(unique.len(), count);
    }

    #[test]
    fn a_reset_reason_and_a_palette_source_each_have_a_stable_string() {
        assert_eq!(
            ProjectionResetReason::BufferSwitch.as_str(),
            "buffer_switch"
        );
        assert_eq!(
            PaletteProvenance::ClientPreference.as_str(),
            "client_preference"
        );
        assert_eq!(ProjectedBuffer::Alternate.as_str(), "alternate");
    }
}
