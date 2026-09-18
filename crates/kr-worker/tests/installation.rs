//! What building one installation costs, measured rather than reasoned about.
//!
//! Section 8 bounds the state a session may hold resident at 64 MiB and bounds what one subscriber
//! may have queued for it at that subscriber's own send queue. Building the screen a client is
//! installed with sits between the two, and it is the one place where the session could be held
//! twice over: once as the engine's copy of every row and once as the wire pages those rows are
//! converted into. It is not, and this is where that is measured.
//!
//! The measurement is the process's own allocator, counting live bytes and remembering the highest
//! they reached. This test binary holds one test for that reason: a peak is a property of the whole
//! process, so anything else allocating beside it would be measuring something else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_protocol::projection::ProjectionResetReason;
use kr_protocol::scalars::U64;
use kr_protocol::session::Dimensions;
use kr_term::lane::LaneGate;
use kr_worker::projection::TerminalEngine;

/// Bytes currently held by this process, as far as the allocator knows.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The highest [`LIVE`] has reached since it was last reset.
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting what it hands out.
struct Counting;

impl Counting {
    /// Counted from the first allocation this process makes, never switched off: a counter that
    /// began part way through would see frees of memory it never saw taken and would run backwards.
    fn took(size: usize) {
        let live = LIVE.fetch_add(size, Ordering::Relaxed).saturating_add(size);
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    fn gave_back(size: usize) {
        LIVE.fetch_sub(size, Ordering::Relaxed);
    }
}

#[expect(
    unsafe_code,
    reason = "an allocator is the one thing that can say what a construction actually cost, and \
              its trait is unsafe by definition; every call below forwards to the system allocator \
              unchanged and only counts what it returned"
)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            Self::took(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            Self::took(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        Self::gave_back(layout.size());
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            Self::gave_back(layout.size());
            Self::took(new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `work` and returns the highest the process's live bytes reached while it ran.
fn peak_of<T>(work: impl FnOnce() -> T) -> (T, usize) {
    // Whatever the caller built before this is already live and is not what is being measured, so
    // the peak starts from where the process stands rather than from zero.
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let answer = work();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    (answer, peak)
}

fn dimensions(columns: u64, rows: u64) -> Dimensions {
    Dimensions {
        columns: U64::new(columns),
        rows: U64::new(rows),
    }
}

/// A session of this size with every cell of both buffers holding content.
///
/// Each row carries its own hyperlink target and its own text, so no two rows share a string and
/// the screen is as expensive as a screen of this size can reasonably be. The alternate buffer is
/// filled as well, because an installation carries both.
fn filled(columns: u64, rows: u64) -> TerminalEngine {
    let mut engine = TerminalEngine::new(dimensions(columns, rows)).expect("a canonical grid");
    let mut stream = Vec::new();
    for buffer in 0..2 {
        if buffer == 1 {
            stream.extend_from_slice(b"\x1b[?1049h");
        }
        for row in 0..rows {
            let target = format!("https://example.invalid/{buffer}/{row}/{}", "p".repeat(240));
            stream.extend_from_slice(format!("\x1b]8;;{target}\x1b\\").as_bytes());
            for column in 0..columns {
                // A colour of its own for every cell, so no two neighbouring cells share a run:
                // a screen the session holds as one run per cell is the expensive shape, and it is
                // the one an installation has to convert cell by cell.
                let colour = 16 + u32::try_from((row * columns + column) % 200).unwrap_or(0);
                let letter = char::from_u32(
                    0x61 + u32::from(u8::try_from((row + column) % 26).unwrap_or(0)),
                )
                .unwrap_or('a');
                // Combining marks, up to the per-cell content bound, so a cell is not one byte.
                stream.extend_from_slice(
                    format!("\x1b[38;5;{colour}m{letter}\u{0301}\u{0308}\u{0327}").as_bytes(),
                );
            }
            stream.extend_from_slice(b"\x1b[0m\x1b]8;;\x1b\\");
            if row + 1 < rows {
                stream.extend_from_slice(b"\r\n");
            }
        }
    }
    engine.feed(0, &stream, LaneGate::default(), 0);
    engine
}

/// The subscriber queue every installation in this test is built for.
///
/// Small on purpose: what is being measured is the cost of *building* a screen, and a queue that
/// could hold any of these screens whole would let the building hide inside it.
const QUEUE: usize = 256 * 1024;

/// KR-REQ-08.79: building an installation holds a run of rows and the queue, never the screen.
///
/// Two sessions, one small and one sixty times larger, installed for the same subscriber queue. If
/// the construction held the screen, the larger one would cost what the larger screen costs. What
/// it costs instead is what the smaller one costs, plus one run of rows.
#[test]
fn building_an_installation_holds_a_run_of_rows_rather_than_the_screen() {
    let mut short = filled(320, 16);
    let mut tall = filled(320, 160);

    // What the screen itself is worth, as the engine hands it over whole: the restoration a direct
    // attachment is given takes every row of it at once. This is the figure the installation is not
    // allowed to cost.
    let (whole, screen) = peak_of(|| {
        tall.restoration(
            dimensions(320, 160),
            LaneGate::default(),
            0,
            kr_worker::render::Keyboard::Install,
            kr_worker::render::Scope::WholeScreen,
        )
    });
    assert!(
        !whole.1.bytes.is_empty(),
        "the tall session has a screen to hand over"
    );
    assert!(
        screen > 4 * 1024 * 1024,
        "the tall session's screen really is large: {screen} bytes"
    );

    let (short_install, short_peak) = peak_of(|| {
        short.projection_install(
            kr_worker::projection::Window::live(dimensions(320, 16)),
            ProjectionResetReason::Attached,
            LaneGate::default(),
            0,
            QUEUE,
            kr_worker::render::Scope::WholeScreen,
        )
    });
    let (tall_install, tall_peak) = peak_of(|| {
        tall.projection_install(
            kr_worker::projection::Window::live(dimensions(320, 160)),
            ProjectionResetReason::Attached,
            LaneGate::default(),
            0,
            QUEUE,
            kr_worker::render::Scope::WholeScreen,
        )
    });
    let short_install = short_install.expect("the short session installs").0;
    let tall_install = tall_install.expect("the tall session installs").0;
    assert!(
        !short_install.is_empty() && !tall_install.is_empty(),
        "both installations carry a screen"
    );
    assert!(
        tall_install.bytes() <= QUEUE,
        "the tall session's installation fits the queue it was built for: {} bytes",
        tall_install.bytes()
    );

    // Ten times the screen, for the same queue. A construction that held the screen would cost ten
    // times as much; what this costs is the run of rows it converts at a time, the queue it is
    // filling, and the envelopes of the rows it pages.
    assert!(
        tall_peak < short_peak.saturating_mul(2),
        "ten times the screen cost {tall_peak} bytes to install against the short screen's \
         {short_peak}, which is the cost of holding it rather than converting it"
    );
    assert!(
        tall_peak < screen / 2,
        "and building the installation cost less than handing the same screen over whole, which \
         does hold every row: {tall_peak} bytes against {screen}"
    );
}
