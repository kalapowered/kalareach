//! What the backend tells the page, handed to a suite as it is told.
//!
//! A listener that a suite adds in Rust may not hear an event when it is told. Tauri queues an
//! emit that finds the event listeners busy, and a later emit that runs a handler and finds them
//! free delivers it; that emit can find them busy in turn, and then the event is queued again. So
//! an event that the backend tells once, with nothing after it, can wait for good. The
//! page does not meet that: an event reaches the page's own listeners before the Rust ones, on a
//! path that has no queue. A suite that waits for an event the backend tells therefore reads it
//! here, where the backend hands it over. Only the events that a suite waits for are handed over:
//! the pairing, confirmations, standing, connection and settings events, where a computer's own
//! application tells them. The emits that only a phone's application makes are not.

use serde::Serialize;
use tauri::Manager as _;

/// What a suite does with each event the backend hands over: the event's name, and its payload as
/// the page receives it. An application that has no tap managed hands nothing over.
pub struct Tap(Heard);

/// What a [`Tap`] calls for each event: the event's name and its payload.
type Heard = Box<dyn Fn(&str, String) + Send + Sync>;

impl Tap {
    /// A tap that calls `heard` as each event is told.
    pub fn new(heard: impl Fn(&str, String) + Send + Sync + 'static) -> Self {
        Self(Box::new(heard))
    }
}

/// Hands `payload`, told as `event`, to the application's tap, in the same call that tells the page.
pub(crate) fn tap<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    event: &str,
    payload: &impl Serialize,
) {
    if let Some(tap) = app.try_state::<Tap>()
        && let Ok(text) = serde_json::to_string(payload)
    {
        (tap.0)(event, text);
    }
}
