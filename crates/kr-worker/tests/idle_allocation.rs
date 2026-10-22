//! What a session's worker holds, counted in the bytes the process asked the allocator for.
//!
//! Section 8 bounds a session's resident terminal state, with an 8 MiB cache of historical rows
//! beside a separate 64 MiB budget for the canonical screens, and asks that idle-memory tests
//! count what is actually allocated, grids and caches and the costs a session shares, and not only
//! the size of an empty structure. The reservation the budget makes is arithmetic; this measures
//! the other side of it. The measurement is the process's own allocator, so this binary holds one
//! test: a live figure belongs to the whole process, and anything else running beside it would be
//! measured with it.
//!
//! What the allocator does not see is not counted here: the shell and its programs are other
//! processes, and the journal's database allocates inside its own library. The figures are of what
//! this worker's Rust code holds.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_protocol::session::Dimensions;
use kr_term::lane::LaneGate;
use kr_worker::projection::TerminalEngine;

/// Bytes currently held by this process, as far as the allocator knows.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting what it hands out.
struct Counting;

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
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(new_size, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `work` and returns it with what it left allocated.
fn held_by<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    let answer = work();
    let after = LIVE.load(Ordering::Relaxed);
    (answer, after.saturating_sub(before))
}

fn dimensions(columns: u64, rows: u64) -> Dimensions {
    Dimensions::new(columns, rows)
}

fn clock() -> Arc<dyn kr_ipc::clock::SharedClock> {
    Arc::new(kr_ipc::clock::SystemSharedClock)
}

/// The historical-row cache's bound, in bytes: section 8's 8 MiB per session.
const ROW_CACHE_BYTES: usize = 8 * 1024 * 1024;

/// The canonical state's budget, in bytes: section 8's 64 MiB per session.
const SESSION_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Writes every cell of the engine's screen, so the rows a grid allocates on demand are allocated.
fn fill_the_screen(engine: &mut TerminalEngine, cursor: &mut u64, columns: usize, rows: usize) {
    for row in 0..rows {
        let mut line = "x".repeat(columns);
        if row + 1 < rows {
            line.push_str("\r\n");
        }
        let _ = engine.feed(*cursor, line.as_bytes(), LaneGate::default());
        *cursor += line.len() as u64;
    }
}

/// KR-REQ-08.79: what a session holds is counted in the bytes its process asked the allocator for,
/// and not in what the budgets reserve. Idle, a grid and a whole worker session hold a small part
/// of the cache's bound and of the budget; a screen written in full holds what its cells cost, so
/// four times the cells hold several times the bytes; and a session that has printed far more
/// than its history keeps holds the history and no more, within the cache's bound, which a batch
/// printed after it is full does not move.
#[test]
fn the_bytes_a_session_holds_idle_and_after_it_has_printed_a_great_deal_are_within_its_budgets() {
    // The idle grids: the canonical size section 27 measures, and one with four times the cells.
    // Neither holds what the budgets reserve: the cache is not made ahead and the screens are
    // allocated as they are written.
    let (small, small_idle) =
        held_by(|| TerminalEngine::new(dimensions(120, 40), clock()).expect("a canonical grid"));
    let (large, large_idle) =
        held_by(|| TerminalEngine::new(dimensions(240, 80), clock()).expect("a canonical grid"));
    eprintln!("idle grid 120x40: {small_idle} bytes; 240x80: {large_idle} bytes");
    assert!(
        small_idle < ROW_CACHE_BYTES / 4 && large_idle < ROW_CACHE_BYTES / 4,
        "an idle grid holds {small_idle} bytes and a larger one {large_idle}, against a cache of \
         {ROW_CACHE_BYTES} and a budget of {SESSION_BUDGET_BYTES}"
    );

    // The screens, written in full: the bytes the allocator holds follow the cells.
    let mut engine = small;
    let mut bigger = large;
    let mut cursor = 0u64;
    let mut bigger_cursor = 0u64;
    let (_, small_filled) = held_by(|| fill_the_screen(&mut engine, &mut cursor, 120, 40));
    let (_, large_filled) = held_by(|| fill_the_screen(&mut bigger, &mut bigger_cursor, 240, 80));
    eprintln!(
        "a screen written in full: 120x40 adds {small_filled} bytes; 240x80 adds {large_filled}"
    );
    drop(bigger);
    assert!(
        small_filled > 0 && large_filled > 2 * small_filled,
        "four times the cells added {large_filled} bytes against {small_filled}"
    );

    // The cache: rows of full width, each cell in a colour of its own, are scrolled off the 120x40
    // screen in batches, until far more has been printed than the history keeps. The allocator
    // holds the rows the history keeps beside the screen, the history is bounded, and a batch
    // printed after it is full adds next to nothing.
    let mut printed = Vec::new();
    let mut line = 0u32;
    for _ in 0..4 {
        let (_, grown) = held_by(|| {
            for _ in 0..1_000 {
                let mut row = String::from("\r\n");
                for column in 0..120u32 {
                    row.push_str(&format!("\x1b[38;5;{}mx", (line + column) % 256));
                }
                line += 1;
                let _ = engine.feed(cursor, row.as_bytes(), LaneGate::default());
                cursor += row.len() as u64;
            }
        });
        printed.push(grown);
    }
    eprintln!("bytes added by each thousand rows of output: {printed:?}");
    let total: usize = printed.iter().sum();
    assert!(
        total <= ROW_CACHE_BYTES + ROW_CACHE_BYTES / 2,
        "after more output than the cache holds, the session keeps {total} bytes beyond its \
         screen, against a cache of {ROW_CACHE_BYTES}"
    );
    assert!(
        printed[0] > 0,
        "the cache holds rows, and the allocator counts them"
    );
    assert!(
        printed[2] + printed[3] <= total / 20,
        "the history is full and the last two thousand rows added {} bytes of {total}",
        printed[2] + printed[3]
    );
    assert!(small_idle + small_filled + total < SESSION_BUDGET_BYTES);
    drop(engine);

    // The shared costs: a worker's whole session, built the way the worker builds it, beside the
    // runtime it runs on, with its shell idle. What the allocator holds is the grid and every
    // structure the session, its history, its broker, its journal handle and its runtime keep
    // beside it.
    let host = kr_ipc::testing::TempHost::create();
    let (idle_worker, worker_bytes) = held_by(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let session = runtime.block_on(async { idle_session(&host) });
        (runtime, session)
    });
    eprintln!("an idle worker session: {worker_bytes} bytes beside its shell");
    assert!(
        worker_bytes > small_idle,
        "a session holds more than its grid: {worker_bytes} bytes against {small_idle}"
    );
    assert!(
        worker_bytes < WORKER_IDLE_BYTES,
        "an idle worker session holds {worker_bytes} bytes, against {WORKER_IDLE_BYTES}"
    );
    // The shell is ended with the session, so nothing of it is left running.
    let (runtime, session) = idle_worker;
    runtime.block_on(async {
        session
            .close(kr_protocol::session::ClosureReason::CloseRequested)
            .1
            .release();
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(30), session.wait_closed()).await;
    });
}

/// The most a worker's Rust code may hold with one idle session, in bytes. Section 27 allows twenty
/// idle workers, their shells and the daemon 500 MiB between them, and the part of that which is
/// this code's own allocation is a small fraction of each worker's share: a session that held the
/// cache's bound or the budget's, ahead of use, would be many times this.
const WORKER_IDLE_BYTES: usize = 2 * 1024 * 1024;

/// Opens a session whose root shell waits for input, and starts the runtime that serves it.
fn idle_session(host: &kr_ipc::testing::TempHost) -> Arc<kr_worker::runtime::SessionRuntime> {
    let session_id =
        kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
    let config = kr_worker::session::SessionConfig {
        session_id,
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: kr_protocol::session::DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: dimensions(120, 40),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: kr_protocol::limits::MAX_SEND_QUEUE_BYTES,
        resident_bytes: kr_worker::history::DEFAULT_RESIDENT_BYTES,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut opened = kr_worker::session::Session::open(config).expect("opens");
    opened.launch().expect("launches");
    Arc::new(kr_worker::runtime::SessionRuntime::start(opened, clock()).expect("starts"))
}
