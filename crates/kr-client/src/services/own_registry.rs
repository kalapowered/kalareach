//! Who may start, and who must stand aside, while the host holds an own-key call.
//!
//! One own-key call at a time runs on a host, and a call the host cannot show is closed blocks the
//! next one: a second call beside a first that may still be running is a second charge on the
//! owner's account. The registry holds that rule in one place. Its state is behind a short mutex
//! that is never held across an await, so the long waits of a start happen while the state says
//! `Starting`, which refuses every other start.
//!
//! The owner's removing the key, or forgetting the calls, first fences the registry: new starts
//! are refused, and every task of an older epoch may do one thing only, which is to hang up a
//! session it holds or learns of.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_protocol::ids::ActionId;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::own_call::{LedgerError, OwnCallLedger};

/// Where the host stands with respect to an own-key call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryState {
    /// No call is starting or running.
    Idle,
    /// A call is being created: the host has asked, or is about to ask, the provider.
    Starting,
    /// A call is running.
    Running,
    /// The owner is removing the key or forgetting the calls. Nothing starts until it is over.
    Settling,
}

/// Why a start is refused.
#[derive(Clone, PartialEq, Eq)]
pub enum StartRefusal {
    /// The owner is removing the key or forgetting the calls.
    Settling,
    /// A call is starting or running on this host.
    InProgress,
    /// A call that is not confirmed closed stands.
    Blocked {
        /// The action the earlier call was started under.
        action_id: ActionId,
        /// The device that started it.
        device_id: String,
        /// When the host asked the provider for it, in milliseconds on the host's clock.
        asked_ms: u64,
    },
    /// The record of calls could not be read, so the host cannot say none stands.
    RecordUnreadable(LedgerError),
}

crate::debug_as_name!(StartRefusal);

/// How a start that a removal waited for came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartEnd {
    /// The start ended and no session of the provider's is in question.
    Ended,
    /// The creation was never answered: the provider may or may not hold a session.
    NeverAnswered,
    /// A session that the fence found arriving was hung up and the provider confirmed it closed.
    LateClosed,
    /// A session that the fence found arriving was hung up and the provider did not confirm it.
    LateUnconfirmed,
}

/// The record of the start in flight, made when the start is admitted, so that a removal that
/// fences between the admission and anything the start writes still finds it.
pub struct StartSlot {
    pub(crate) asked: Instant,
    epoch: u64,
    end: Mutex<Option<StartEnd>>,
    done: Notify,
}

impl StartSlot {
    fn new(epoch: u64) -> Self {
        Self {
            asked: Instant::now(),
            epoch,
            end: Mutex::new(None),
            done: Notify::new(),
        }
    }

    pub(crate) fn finish(&self, end: StartEnd) {
        let mut held = self.end.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_none() {
            *held = Some(end);
        }
        drop(held);
        self.done.notify_waiters();
    }

    pub(crate) fn ended(&self) -> Option<StartEnd> {
        *self.end.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolves when the start has ended or `until` has come, whichever is first.
    pub(crate) async fn wait_until(&self, until: Instant) -> Option<StartEnd> {
        loop {
            let notified = self.done.notified();
            tokio::pin!(notified);
            // Registered before the state is read, so a finish between the two is not missed.
            notified.as_mut().enable();
            if let Some(end) = self.ended() {
                return Some(end);
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                return self.ended();
            }
        }
    }
}

crate::debug_as_name!(StartSlot);

/// What a start holds while it is the one start: dropping it without [`CallRegistry::running`]
/// or [`CallRegistry::finished`] returns the registry to `Idle`.
pub struct StartTicket {
    registry: Arc<CallRegistry>,
    epoch: u64,
    live: bool,
    slot: Arc<StartSlot>,
}

impl StartTicket {
    /// The ownership epoch this start began in. A task whose epoch is not the registry's current
    /// one may not adopt a creation, write a row state or write a sideband command.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The record of this start, which the owner of the start ends with
    /// [`CallRegistry::end_start`].
    #[must_use]
    pub fn slot(&self) -> Arc<StartSlot> {
        Arc::clone(&self.slot)
    }
}

impl fmt::Debug for StartTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartTicket")
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl Drop for StartTicket {
    fn drop(&mut self) {
        if self.live {
            self.registry.release(self.epoch, RegistryState::Starting);
            self.registry.end_start(&self.slot, StartEnd::Ended);
        }
    }
}

struct Inner {
    state: RegistryState,
    epoch: u64,
    slot: Option<Arc<StartSlot>>,
}

#[derive(Default)]
struct Tasks {
    running: Mutex<usize>,
    idle: Notify,
}

/// What a task that may use the key or write a row holds while it runs. A removal waits for every
/// token before it lets the registry go.
pub struct TaskToken {
    tasks: Arc<Tasks>,
}

impl Drop for TaskToken {
    fn drop(&mut self) {
        let mut running = self
            .tasks
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *running = running.saturating_sub(1);
        let none = *running == 0;
        drop(running);
        if none {
            self.tasks.idle.notify_waiters();
        }
    }
}

crate::debug_as_name!(TaskToken);

/// The registry of the host's own-key calls.
pub struct CallRegistry {
    inner: Mutex<Inner>,
    ledger: Arc<dyn OwnCallLedger>,
    tasks: Arc<Tasks>,
}

impl fmt::Debug for CallRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallRegistry")
            .finish_non_exhaustive()
    }
}

impl CallRegistry {
    /// A registry over the host's call record, with nothing starting.
    #[must_use]
    pub fn new(ledger: Arc<dyn OwnCallLedger>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                state: RegistryState::Idle,
                epoch: 1,
                slot: None,
            }),
            ledger,
            tasks: Arc::new(Tasks::default()),
        })
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where the registry stands now.
    #[must_use]
    pub fn state(&self) -> RegistryState {
        self.inner().state
    }

    /// The current ownership epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.inner().epoch
    }

    /// Makes the caller the one start, or says why it may not be.
    ///
    /// Refuses while the registry settles, while a call is starting or running, and while any
    /// stored call is not `Closed`. A `Closed` row blocks nothing.
    ///
    /// # Errors
    ///
    /// Returns the reason the start is refused.
    pub fn begin_start(self: &Arc<Self>) -> Result<StartTicket, StartRefusal> {
        let mut inner = self.inner();
        match inner.state {
            RegistryState::Settling => return Err(StartRefusal::Settling),
            RegistryState::Starting | RegistryState::Running => {
                return Err(StartRefusal::InProgress);
            }
            RegistryState::Idle => {}
        }
        // Read under the mutex, so no second start can pass between this read and the change of
        // state below. The read is a file read of a few rows, not a wait on the provider.
        let rows = self.ledger.rows().map_err(StartRefusal::RecordUnreadable)?;
        if let Some(blocking) = rows.iter().find(|row| row.state.blocks_a_start()) {
            return Err(StartRefusal::Blocked {
                action_id: blocking.call.action_id,
                device_id: blocking.call.device_id.clone(),
                asked_ms: blocking.call.asked_ms,
            });
        }
        inner.state = RegistryState::Starting;
        let slot = Arc::new(StartSlot::new(inner.epoch));
        inner.slot = Some(Arc::clone(&slot));
        Ok(StartTicket {
            registry: Arc::clone(self),
            epoch: inner.epoch,
            live: true,
            slot,
        })
    }

    /// Runs `change` while no call is starting, running or standing, and while no start can be
    /// admitted, because the registry's own lock is held across it. This is how the key is
    /// replaced: no start can read the old key and have it replaced before it is done with it.
    ///
    /// # Errors
    ///
    /// Returns why a start would be refused now, and runs nothing.
    pub fn while_idle<T>(&self, change: impl FnOnce() -> T) -> Result<T, StartRefusal> {
        let inner = self.inner();
        match inner.state {
            RegistryState::Settling => return Err(StartRefusal::Settling),
            RegistryState::Starting | RegistryState::Running => {
                return Err(StartRefusal::InProgress);
            }
            RegistryState::Idle => {}
        }
        let rows = self.ledger.rows().map_err(StartRefusal::RecordUnreadable)?;
        if let Some(blocking) = rows.iter().find(|row| row.state.blocks_a_start()) {
            return Err(StartRefusal::Blocked {
                action_id: blocking.call.action_id,
                device_id: blocking.call.device_id.clone(),
                asked_ms: blocking.call.asked_ms,
            });
        }
        let changed = change();
        drop(inner);
        Ok(changed)
    }

    /// The start in flight, or the last one a fence found.
    #[must_use]
    pub fn slot(&self) -> Option<Arc<StartSlot>> {
        self.inner().slot.clone()
    }

    /// Records how a start came out. A start that ends before any fence leaves no record, so a
    /// later removal does not tell of it; one that a fence found leaves it for the settle to read.
    pub fn end_start(&self, slot: &Arc<StartSlot>, end: StartEnd) {
        slot.finish(end);
        let mut inner = self.inner();
        if inner.epoch == slot.epoch
            && inner
                .slot
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, slot))
        {
            inner.slot = None;
        }
    }

    /// Forgets `slot` once a settle has told what became of its start, so that a later settle
    /// with no start in flight does not tell that start's end again.
    pub fn clear_slot(&self, slot: &Arc<StartSlot>) {
        let mut inner = self.inner();
        if inner
            .slot
            .as_ref()
            .is_some_and(|held| Arc::ptr_eq(held, slot))
        {
            inner.slot = None;
        }
    }

    /// A token for a task that may use the key or write a row until it ends.
    #[must_use]
    pub fn track(&self) -> TaskToken {
        *self
            .tasks
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += 1;
        TaskToken {
            tasks: Arc::clone(&self.tasks),
        }
    }

    /// Waits until no tracked task is left, at most `bound`. Says whether none is.
    pub async fn quiesce(&self, bound: Duration) -> bool {
        let until = Instant::now() + bound;
        loop {
            let notified = self.tasks.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *self
                .tasks
                .running
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                == 0
            {
                return true;
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                return *self
                    .tasks
                    .running
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    == 0;
            }
        }
    }

    /// The start's call is running. Returns whether the ticket's epoch still owns the registry:
    /// `false` means a fence came between, and the caller owns no call.
    #[must_use]
    pub fn running(&self, mut ticket: StartTicket) -> bool {
        ticket.live = false;
        let mut inner = self.inner();
        if inner.epoch == ticket.epoch && inner.state == RegistryState::Starting {
            inner.state = RegistryState::Running;
            true
        } else {
            false
        }
    }

    /// The start ended without a running call, and came out as `end`.
    pub fn finished(&self, mut ticket: StartTicket, end: StartEnd) {
        ticket.live = false;
        self.release(ticket.epoch, RegistryState::Starting);
        self.end_start(&ticket.slot, end);
    }

    /// The running call ended.
    pub fn call_ended(&self, epoch: u64) {
        self.release(epoch, RegistryState::Running);
    }

    fn release(&self, epoch: u64, from: RegistryState) {
        let mut inner = self.inner();
        if inner.epoch == epoch && inner.state == from {
            inner.state = RegistryState::Idle;
        }
    }

    /// Fences the registry for a removal or a forget: new starts are refused, the epoch moves on,
    /// and the state before is returned so the caller knows what it must wait for.
    ///
    /// A fence is held until [`unfence`](Self::unfence). A second fence while one is held is
    /// refused with `None`, so two removals do not settle at once.
    pub fn fence(&self) -> Option<Fenced> {
        let mut inner = self.inner();
        if inner.state == RegistryState::Settling {
            return None;
        }
        let before = inner.state;
        inner.state = RegistryState::Settling;
        inner.epoch += 1;
        Some(Fenced {
            before,
            epoch: inner.epoch,
        })
    }

    /// Ends a fence: the registry is idle and starts are taken again.
    pub fn unfence(&self) {
        let mut inner = self.inner();
        if inner.state == RegistryState::Settling {
            inner.state = RegistryState::Idle;
        }
    }
}

/// What a fence found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fenced {
    /// What the registry was doing when it was fenced.
    pub before: RegistryState,
    /// The epoch after the fence: no task of an earlier epoch may write a row state.
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::own_call::{CallRow, CallState, LedgerResult, NewCall};
    use kr_protocol::scalars::Uuid;

    /// A ledger in memory, so these cases read the registry's rules and nothing of a file.
    #[derive(Debug, Default)]
    struct Rows {
        rows: Mutex<Vec<CallRow>>,
        unreadable: Mutex<bool>,
    }

    impl Rows {
        fn with(state: CallState, byte: u8) -> Arc<Self> {
            let rows = Self::default();
            rows.rows.lock().expect("the rows").push(row(state, byte));
            Arc::new(rows)
        }
    }

    fn row(state: CallState, byte: u8) -> CallRow {
        CallRow {
            call: NewCall {
                call_id: format!("call-{byte}"),
                attempt_id: format!("attempt-{byte}"),
                action_id: ActionId::new(Uuid::from_bytes([byte; 16])),
                device_id: format!("device-{byte}"),
                asked_ms: u64::from(byte) * 1_000,
                closes_at_ms: u64::from(byte) * 1_000 + 1_800_000,
            },
            state,
            provider_session_id: (state != CallState::Creating).then(|| "sess".to_owned()),
            provider_expires_ms: None,
            closed_ms: (state == CallState::Closed).then_some(1),
        }
    }

    impl OwnCallLedger for Rows {
        fn begin(&self, _call: &NewCall) -> LedgerResult<()> {
            Ok(())
        }
        fn record_id(&self, _: &str, _: &str, _: Option<u64>) -> LedgerResult<()> {
            Ok(())
        }
        fn record_state(&self, _: &str, _: CallState) -> LedgerResult<()> {
            Ok(())
        }
        fn record_closed(&self, _: &str, _: u64) -> LedgerResult<()> {
            Ok(())
        }
        fn rows(&self) -> LedgerResult<Vec<CallRow>> {
            if *self.unreadable.lock().expect("the flag") {
                return Err(LedgerError::said("the record is unreadable"));
            }
            Ok(self.rows.lock().expect("the rows").clone())
        }
        fn delete(&self, _: &str) -> LedgerResult<()> {
            Ok(())
        }
        fn forget_all(&self) -> LedgerResult<u64> {
            Ok(0)
        }
    }

    /// One start at a time: the first is the start, the second is told one is in progress, and a
    /// start that ended without a call frees the next.
    #[test]
    fn a_second_start_is_refused_while_one_is_starting_or_running_and_a_dropped_ticket_frees_it() {
        let registry = CallRegistry::new(Arc::new(Rows::default()));
        let first = registry.begin_start().expect("the first start");
        assert_eq!(registry.state(), RegistryState::Starting);
        assert_eq!(
            registry.begin_start().expect_err("a second start"),
            StartRefusal::InProgress
        );

        drop(first);
        assert_eq!(
            registry.state(),
            RegistryState::Idle,
            "a dropped start frees the host"
        );

        let second = registry.begin_start().expect("the next start");
        assert!(registry.running(second), "the call runs");
        assert_eq!(registry.state(), RegistryState::Running);
        assert_eq!(
            registry.begin_start().expect_err("a start beside a call"),
            StartRefusal::InProgress
        );
        registry.call_ended(registry.epoch());
        assert_eq!(registry.state(), RegistryState::Idle);
    }

    /// A row that is not closed blocks a start and names the earlier action, device and time; a
    /// closed row blocks nothing.
    #[test]
    fn a_row_that_is_not_closed_blocks_a_start_and_a_closed_row_does_not() {
        for state in [
            CallState::Creating,
            CallState::Open,
            CallState::Closing,
            CallState::Unresolved,
        ] {
            let registry = CallRegistry::new(Rows::with(state, 7));
            assert_eq!(
                registry.begin_start().expect_err("a standing call blocks"),
                StartRefusal::Blocked {
                    action_id: ActionId::new(Uuid::from_bytes([7; 16])),
                    device_id: "device-7".to_owned(),
                    asked_ms: 7_000,
                },
                "{state:?}"
            );
            assert_eq!(
                registry.state(),
                RegistryState::Idle,
                "a refused start holds nothing"
            );
        }
        let registry = CallRegistry::new(Rows::with(CallState::Closed, 7));
        assert!(
            registry.begin_start().is_ok(),
            "a closed row blocks nothing"
        );
    }

    /// A record that cannot be read is not "none stands".
    #[test]
    fn a_record_that_cannot_be_read_refuses_the_start() {
        let rows = Arc::new(Rows::default());
        *rows.unreadable.lock().expect("the flag") = true;
        let registry = CallRegistry::new(rows);
        assert!(matches!(
            registry.begin_start(),
            Err(StartRefusal::RecordUnreadable(_))
        ));
        assert_eq!(registry.state(), RegistryState::Idle);
    }

    /// A fence refuses starts and moves the epoch; a start that began before it neither adopts a
    /// call nor frees the fence; a second fence is refused until the first ends.
    #[test]
    fn a_fence_refuses_starts_moves_the_epoch_and_is_held_until_it_ends() {
        let registry = CallRegistry::new(Arc::new(Rows::default()));
        let early = registry.begin_start().expect("a start");
        let epoch_before = registry.epoch();

        let fenced = registry.fence().expect("the fence");
        assert_eq!(
            fenced.before,
            RegistryState::Starting,
            "it says what it found"
        );
        assert!(fenced.epoch > epoch_before);
        assert_eq!(registry.state(), RegistryState::Settling);
        assert_eq!(
            registry.begin_start().expect_err("a start while settling"),
            StartRefusal::Settling
        );
        assert!(
            registry.fence().is_none(),
            "two removals do not settle at once"
        );

        assert!(
            !registry.running(early),
            "a start of an older epoch adopts no call"
        );
        assert_eq!(
            registry.state(),
            RegistryState::Settling,
            "and does not end the fence"
        );

        registry.unfence();
        assert_eq!(registry.state(), RegistryState::Idle);
        assert!(registry.begin_start().is_ok(), "starts are taken again");
    }

    /// The call that ended under an older epoch does not free a registry that a later start holds.
    #[test]
    fn a_call_that_ends_under_an_older_epoch_frees_nothing() {
        let registry = CallRegistry::new(Arc::new(Rows::default()));
        let old_epoch = registry.epoch();
        registry.fence().expect("the fence");
        registry.unfence();
        let ticket = registry.begin_start().expect("a start");
        assert!(registry.running(ticket));

        registry.call_ended(old_epoch);
        assert_eq!(registry.state(), RegistryState::Running);
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_runs_only_while_idle_and_a_start_cannot_pass_it() {
        let rows = Rows::with(CallState::Closed, 1);
        let registry = CallRegistry::new(rows);
        assert_eq!(registry.while_idle(|| 7), Ok(7));
        let ticket = registry.begin_start().expect("a start");
        assert_eq!(registry.while_idle(|| 7), Err(StartRefusal::InProgress));
        drop(ticket);
        let blocked = CallRegistry::new(Rows::with(CallState::Open, 2));
        assert!(matches!(
            blocked.while_idle(|| 7),
            Err(StartRefusal::Blocked { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_removal_waits_for_every_task_it_tracks() {
        let registry = CallRegistry::new(Rows::with(CallState::Closed, 1));
        let token = registry.track();
        assert!(!registry.quiesce(Duration::from_secs(1)).await);
        let release = async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(token);
        };
        let (quiet, ()) = tokio::join!(registry.quiesce(Duration::from_secs(5)), release);
        assert!(quiet);
    }

    #[test]
    fn a_start_that_ends_before_a_fence_leaves_no_slot_and_one_a_fence_found_stays() {
        let registry = CallRegistry::new(Rows::with(CallState::Closed, 1));
        let ticket = registry.begin_start().expect("a start");
        assert!(registry.slot().is_some(), "the slot is made at admission");
        registry.finished(ticket, StartEnd::Ended);
        assert!(
            registry.slot().is_none(),
            "a normal end leaves nothing to tell"
        );
        let ticket = registry.begin_start().expect("a start");
        let _fence = registry.fence().expect("a fence");
        registry.finished(ticket, StartEnd::NeverAnswered);
        assert_eq!(
            registry.slot().and_then(|slot| slot.ended()),
            Some(StartEnd::NeverAnswered)
        );
    }
}
