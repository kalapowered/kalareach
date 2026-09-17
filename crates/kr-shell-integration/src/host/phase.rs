//! The phase gate, and the rule that makes a root method a root method.
//!
//! Section 7 separates authentication from qualification, and the difference decides real
//! behaviour: a session whose bridge is authenticated but whose startup files are still running
//! accepts input, because a profile that asks a question must not deadlock, and refuses a launch,
//! because nothing has qualified yet. [`IntegrationPhase`] holds those rules; this is where the
//! worker applies them, and where a loss becomes either a new phase or a closed session.
//!
//! The second rule here is section 23's: `root.editor.enter`, `root.editor.leave`,
//! `root.editor.fence`, `root.eof.detach` and `root.command.accepted` are reachable only from this
//! session's validated root registration over private IPC. They are not reachable from a paired
//! device, from a plugin, from another local client of the same user, or from a second connection
//! on the bridge endpoint itself.

use crate::contract::qualification::{
    IntegrationLoss, IntegrationPhase, LossOutcome, ShellKind, phase_after,
};

/// The five root methods, exactly as section 23 lists them.
pub const ROOT_METHODS: &[&str] = &[
    "root.editor.enter",
    "root.editor.leave",
    "root.editor.fence",
    "root.eof.detach",
    "root.command.accepted",
];

/// Returns true when a method is one of the root-integration methods.
#[must_use]
pub fn is_root_method(method: &str) -> bool {
    ROOT_METHODS.contains(&method)
}

/// What a session lost, and what the worker does about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossDecision {
    /// The phase the session is in afterwards, when it carries on.
    pub phase: IntegrationPhase,
    /// True when the creating session closes and records its diagnostics instead.
    pub closes_session: bool,
}

/// The session's integration phase, and what it permits.
///
/// One value, advanced by the two events that move it forward and by the losses that move it back.
/// Everything that asks "may this happen?" asks here rather than reading a collection of flags,
/// because a second place to record the same fact is a second place for it to be wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseGate {
    phase: IntegrationPhase,
    kind: Option<ShellKind>,
    /// Why the session is where it is, for diagnostics and for session status.
    history: Vec<IntegrationLoss>,
}

impl PhaseGate {
    /// Builds a gate for a managed session whose bridge has not connected yet.
    #[must_use]
    pub const fn unauthenticated() -> Self {
        Self {
            phase: IntegrationPhase::Unauthenticated,
            kind: None,
            history: Vec::new(),
        }
    }

    /// Builds a gate for a session that claims none of this contract.
    ///
    /// A `native_compat` session is terminal-only from the start: it never registers a root
    /// integration, so its input forwards like any application's and its Ctrl-D is the shell's own.
    #[must_use]
    pub const fn terminal_only() -> Self {
        Self {
            phase: IntegrationPhase::TerminalOnly,
            kind: None,
            history: Vec::new(),
        }
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn phase(&self) -> IntegrationPhase {
        self.phase
    }

    /// Returns the shell the registered bridge declared, once one has.
    #[must_use]
    pub const fn shell(&self) -> Option<ShellKind> {
        self.kind
    }

    /// Returns the losses this session has recorded, in the order they happened.
    #[must_use]
    pub fn losses(&self) -> &[IntegrationLoss] {
        &self.history
    }

    /// Records an accepted handshake.
    ///
    /// The bridge is now authenticated and ABI-checked, which is what lets external input reach the
    /// terminal. Rich launch, attribution and a create success wait for qualification.
    pub const fn authenticated(&mut self, kind: ShellKind) {
        self.phase = IntegrationPhase::Authenticated;
        self.kind = Some(kind);
    }

    /// Records the activation that follows the user's startup files.
    ///
    /// Only an authenticated session qualifies. A `hooks_activated` report from a session that has
    /// already lost its hooks does not promote it back: recovery is a new create request.
    pub const fn qualified(&mut self) -> bool {
        if matches!(self.phase, IntegrationPhase::Authenticated) {
            self.phase = IntegrationPhase::Qualified;
            return true;
        }
        false
    }

    /// Applies a loss and says what the session does about it.
    pub fn lost(&mut self, loss: IntegrationLoss) -> LossDecision {
        self.history.push(loss);
        match phase_after(self.phase, loss) {
            LossOutcome::Phase(phase) => {
                self.phase = phase;
                LossDecision {
                    phase,
                    closes_session: false,
                }
            }
            LossOutcome::CloseSession => LossDecision {
                phase: self.phase,
                closes_session: true,
            },
        }
    }

    /// Returns true when a client's input may reach the terminal.
    #[must_use]
    pub const fn accepts_external_input(&self) -> bool {
        self.phase.accepts_external_input()
    }

    /// Returns true when the session may report itself ready and a create may succeed.
    #[must_use]
    pub const fn reports_ready(&self) -> bool {
        self.phase.reports_ready()
    }

    /// Returns true when a launch may be admitted at all.
    #[must_use]
    pub const fn permits_launch(&self) -> bool {
        self.phase.permits_launch()
    }

    /// Returns true when an accepted line may be attributed to an attachment.
    #[must_use]
    pub const fn permits_attribution(&self) -> bool {
        self.phase.permits_attribution()
    }

    /// Returns true when an eligible end-of-file gesture is still consumed with the hint.
    #[must_use]
    pub const fn consumes_eligible_eof(&self) -> bool {
        self.phase.consumes_eligible_eof()
    }

    /// Returns true when a fence exchange may be started or published.
    ///
    /// A retry is asked for only where a fence could stand. Below that phase the reader's entry and
    /// idle callbacks are recorded and answered, and no exchange begins.
    #[must_use]
    pub const fn retains_fence(&self) -> bool {
        self.phase.retains_fence()
    }
}

impl Default for PhaseGate {
    fn default() -> Self {
        Self::unauthenticated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_loss_before_qualification_closes_the_creating_session() {
        for phase in [
            IntegrationPhase::Unauthenticated,
            IntegrationPhase::Authenticated,
        ] {
            for loss in IntegrationLoss::ALL {
                let mut gate = PhaseGate {
                    phase,
                    kind: None,
                    history: Vec::new(),
                };
                assert!(
                    gate.lost(*loss).closes_session,
                    "{phase:?} + {loss:?} closes the creating session"
                );
            }
        }
    }

    #[test]
    fn a_live_session_that_loses_its_hooks_keeps_the_fail_safe_gesture() {
        let mut gate = PhaseGate::unauthenticated();
        gate.authenticated(ShellKind::Zsh);
        assert!(gate.accepts_external_input());
        assert!(!gate.permits_launch());
        assert!(!gate.reports_ready());
        assert!(gate.qualified());
        assert!(gate.permits_launch());
        let decision = gate.lost(IntegrationLoss::SemanticHookLoss);
        assert!(!decision.closes_session);
        assert_eq!(decision.phase, IntegrationPhase::Degraded);
        assert!(!gate.permits_launch());
        assert!(!gate.permits_attribution());
        assert!(!gate.retains_fence());
        assert!(gate.consumes_eligible_eof());
    }

    #[test]
    fn an_unqualified_replacement_is_visibly_terminal_only() {
        let mut gate = PhaseGate::unauthenticated();
        gate.authenticated(ShellKind::Bash);
        assert!(gate.qualified());
        let decision = gate.lost(IntegrationLoss::UnqualifiedRootReplacement);
        assert_eq!(decision.phase, IntegrationPhase::TerminalOnly);
        assert!(!gate.consumes_eligible_eof());
        assert!(gate.accepts_external_input());
        assert_eq!(
            gate.losses(),
            &[IntegrationLoss::UnqualifiedRootReplacement]
        );
    }

    #[test]
    fn only_the_five_root_methods_are_root_methods() {
        assert_eq!(ROOT_METHODS.len(), 5);
        for method in ROOT_METHODS {
            assert!(is_root_method(method));
        }
        assert!(!is_root_method("shell.launch"));
        assert!(!is_root_method("input.write"));
    }
}
