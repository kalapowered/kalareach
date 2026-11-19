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

use kr_protocol::ids::ActionId;

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
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// What a start holds while it is the one start: dropping it without [`CallRegistry::running`]
/// or [`CallRegistry::finished`] returns the registry to `Idle`.
pub struct StartTicket {
    registry: Arc<CallRegistry>,
    epoch: u64,
    live: bool,
}

impl StartTicket {
    /// The ownership epoch this start began in. A task whose epoch is not the registry's current
    /// one may not adopt a creation, write a row state or write a sideband command.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
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
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: RegistryState,
    epoch: u64,
}

/// The registry of the host's own-key calls.
pub struct CallRegistry {
    inner: Mutex<Inner>,
    ledger: Arc<dyn OwnCallLedger>,
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
            }),
            ledger,
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
        Ok(StartTicket {
            registry: Arc::clone(self),
            epoch: inner.epoch,
            live: true,
        })
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

    /// The start ended without a running call.
    pub fn finished(&self, mut ticket: StartTicket) {
        ticket.live = false;
        self.release(ticket.epoch, RegistryState::Starting);
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
                return Err(LedgerError("the record is unreadable".to_owned()));
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
}
