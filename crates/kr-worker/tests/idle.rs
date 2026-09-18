//! What an idle session and an idle view hold.
//!
//! Section 27 measures a host's idle footprint by reading the resident size of twenty session
//! processes, their shells and the daemon holding thirty-two views. That figure is a machine's as
//! much as a program's: it moves with what else is running. This is the part underneath it that
//! this crate owns, measured where it cannot move - the bytes this process allocates for a session
//! of that geometry before anything has been printed into it, and the bytes one more installed view
//! adds to that.
//!
//! The measurement is the process's own allocator, so this binary holds one test: a peak and a
//! live figure belong to the whole process, and anything else building a screen beside it would be
//! measuring something else.

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

/// Runs `work` and returns what it left allocated when it was done.
///
/// Not the peak: what a call *keeps*, which is what an idle session and an idle view cost.
fn held_by<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    let answer = work();
    let after = LIVE.load(Ordering::Relaxed);
    (answer, after.saturating_sub(before))
}

fn dimensions(columns: u64, rows: u64) -> Dimensions {
    Dimensions {
        columns: U64::new(columns),
        rows: U64::new(rows),
    }
}

/// The canonical size section 27 measures a host's idle footprint at.
const IDLE_GEOMETRY: (u64, u64) = (120, 40);

/// The queue a view's screen is built for, which is the session's own default.
const QUEUE: usize = 8 * 1024 * 1024;

/// What one idle session may hold, before anything has been printed into it.
///
/// Section 8 bounds a session's resident canonical state at 64 MiB. An empty session of the size
/// section 27 measures holds a small fraction of that, and this pins it where a resident-size
/// reading cannot: in the bytes this process asked the allocator for.
const IDLE_SESSION_BYTES: usize = 4 * 1024 * 1024;

/// What one view may leave behind once it has been installed.
///
/// A projected client is installed once and then sent bounded updates. What the session keeps for it
/// is the base it holds and the window that base was built for; the screen itself goes to that
/// subscriber's queue, so a view costs a few kibibytes rather than a screen.
const IDLE_VIEW_BYTES: usize = 16 * 1024;

/// KR-PERF-003: an idle session and an installed view hold what they are supposed to hold.
#[test]
fn an_idle_session_and_an_installed_view_hold_what_they_are_supposed_to() {
    let (engine, session) = held_by(|| {
        TerminalEngine::new(dimensions(IDLE_GEOMETRY.0, IDLE_GEOMETRY.1)).expect("a canonical grid")
    });
    let mut engine = engine;
    assert!(
        session < IDLE_SESSION_BYTES,
        "an idle session of {}x{} holds {session} bytes",
        IDLE_GEOMETRY.0,
        IDLE_GEOMETRY.1
    );

    // One view: the screen is built, handed over, and what stays behind is the base the session
    // keeps for it. Dropping the events here is the subscriber's queue taking them.
    let mut bases = kr_worker::snapshot::Bases::new();
    let first = kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid());
    let (_, view) = held_by(|| {
        install_for(&mut engine, &mut bases, first, dimensions(80, 24));
    });
    assert_eq!(bases.len(), 1, "the session is holding one view's base");
    assert!(
        view < IDLE_VIEW_BYTES,
        "an installed view leaves {view} bytes behind, which is more than the base it holds"
    );

    // And each view after it costs about the same: what a session keeps for a view is one base, so
    // eight of them cost eight bases rather than eight screens.
    let mut added = Vec::new();
    for window in [
        (60, 20),
        (100, 30),
        (40, 12),
        (72, 24),
        (90, 18),
        (50, 16),
        (110, 36),
    ] {
        let attachment = kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid());
        let (_, cost) = held_by(|| {
            install_for(
                &mut engine,
                &mut bases,
                attachment,
                dimensions(window.0, window.1),
            );
        });
        added.push(cost);
    }
    assert_eq!(bases.len(), 8, "the session is holding every view's base");
    let total: usize = added.iter().sum();
    assert!(
        total < IDLE_VIEW_BYTES,
        "seven more views left {total} bytes behind between them, after the first one's {view}: \
         {added:?}"
    );
}

/// Installs one screen for one view and records the base the session keeps for it.
fn install_for(
    engine: &mut TerminalEngine,
    bases: &mut kr_worker::snapshot::Bases,
    attachment: kr_protocol::ids::AttachmentId,
    window: Dimensions,
) {
    let (update, _) = engine
        .projection_install(
            window,
            kr_worker::projection::ViewportAnchor::LiveScreen,
            ProjectionResetReason::Attached,
            LaneGate::default(),
            0,
            QUEUE,
            kr_worker::render::Scope::WholeScreen,
        )
        .expect("a screen");
    bases.record(
        attachment,
        kr_worker::snapshot::Held {
            base: update.base,
            viewport: engine
                .anchored_viewport(window, kr_worker::projection::ViewportAnchor::LiveScreen),
        },
    );
}
