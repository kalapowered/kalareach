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

use kr_protocol::method::{Method, MethodGroup};

use crate::contract::qualification::{
    IntegrationLoss, IntegrationPhase, LossOutcome, ShellKind, phase_after,
};

/// Returns the root-integration methods, read from the protocol's own registry.
///
/// The list is not written out here. Section 23 puts each method in exactly one group, and the
/// registry is where that is recorded; a second copy of the five names would be a second answer to
/// a question the protocol has already settled, and it would go stale the first time a method
/// joined the group.
#[must_use]
pub fn root_methods() -> Vec<Method> {
    Method::ALL
        .iter()
        .copied()
        .filter(|method| is_root_method(*method))
        .collect()
}

/// Returns true when a method belongs to the root-integration group.
#[must_use]
pub fn is_root_method(method: Method) -> bool {
    method.entry().group == MethodGroup::RootIntegration
}

/// Returns true when a method name belongs to the root-integration group.
///
/// An unlisted name is not a root method; it is not a method at all, and the registry refuses it
/// before this question is asked.
#[must_use]
pub fn is_root_method_name(name: &str) -> bool {
    Method::from_wire(name).is_some_and(is_root_method)
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
    /// [`Self::reports_ready`] stays false for it, because what it reports is managed
    /// qualification; such a session is created and reported ready by its own launch path.
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

    /// Records an accepted handshake, and returns whether it moved the session forward.
    ///
    /// The bridge is now authenticated and ABI-checked, which is what lets external input reach the
    /// terminal. Rich launch, attribution and a create success wait for qualification.
    ///
    /// Only a session that has not authenticated one yet. A session that has already lost its
    /// hooks or its root shell does not recover by registering again: section 7 makes an explicit
    /// compatibility retry a new create request, and promoting a degraded session here would let a
    /// second bridge undo that.
    #[must_use]
    pub const fn authenticated(&mut self, kind: ShellKind) -> bool {
        if matches!(self.phase, IntegrationPhase::Unauthenticated) {
            self.phase = IntegrationPhase::Authenticated;
            self.kind = Some(kind);
            return true;
        }
        false
    }

    /// Records the activation that follows the user's startup files.
    ///
    /// Only an authenticated session qualifies. A `hooks_activated` report from a session that has
    /// already lost its hooks does not promote it back: recovery is a new create request.
    #[must_use]
    pub const fn qualified(&mut self) -> bool {
        if matches!(self.phase, IntegrationPhase::Authenticated) {
            self.phase = IntegrationPhase::Qualified;
            return true;
        }
        false
    }

    /// Applies a loss and says what the session does about it.
    ///
    /// A [`LossDecision`] whose `closes_session` is set leaves the phase where it was: there is no
    /// phase for "closing", and the caller closes the session rather than recording a demotion it
    /// would then have to explain. So the answer has to be acted on, not read and dropped.
    #[must_use]
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

    /// Returns true when the *managed* contract is complete enough to report the session ready.
    ///
    /// Only a qualified session. It is not the whole of "may this create succeed?": a
    /// `native_compat` session claims none of this contract and never qualifies, and whether its
    /// creation succeeded is decided by its own launch rather than here.
    #[must_use]
    pub const fn reports_ready(&self) -> bool {
        self.phase.reports_ready()
    }

    /// Returns true when this session's integration has qualified at least once.
    ///
    /// Not the same question as [`Self::reports_ready`]. A session that qualified and then lost its
    /// hooks is degraded rather than unqualified: it is a session somebody is using, and whoever
    /// asks this is asking whether it ever became one, not whether everything still works. A
    /// session that never got there answers false whatever happens to it afterwards.
    #[must_use]
    pub const fn ever_qualified(&self) -> bool {
        matches!(
            self.phase,
            IntegrationPhase::Qualified
                | IntegrationPhase::Degraded
                | IntegrationPhase::TerminalOnly
        )
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
        assert!(gate.authenticated(ShellKind::Zsh));
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
    fn a_session_that_never_qualified_says_so_and_one_that_degraded_does_not() {
        // Two different questions. A worker answers a daemon's proof for a session somebody is
        // using, and a session that lost its hooks is one of those; a session whose reader never
        // came up is not one yet, whatever it is doing.
        let mut gate = PhaseGate::unauthenticated();
        assert!(!gate.ever_qualified(), "nothing has authenticated yet");
        assert!(gate.authenticated(ShellKind::Zsh));
        assert!(
            !gate.ever_qualified(),
            "the startup files are still running"
        );
        assert!(gate.qualified());
        assert!(gate.ever_qualified());

        for loss in [
            IntegrationLoss::SemanticHookLoss,
            IntegrationLoss::BridgeDisconnected,
            IntegrationLoss::PostStartupFailure,
            IntegrationLoss::UnqualifiedRootReplacement,
        ] {
            let mut degraded = PhaseGate::unauthenticated();
            assert!(degraded.authenticated(ShellKind::Zsh));
            assert!(degraded.qualified());
            let _ = degraded.lost(loss);
            assert!(
                degraded.ever_qualified(),
                "{loss:?} leaves a session that was live"
            );
            assert!(!degraded.reports_ready(), "and one that is not ready");
        }

        // A session that never qualified stays unqualified through a loss as well.
        let mut early = PhaseGate::unauthenticated();
        assert!(early.authenticated(ShellKind::Bash));
        let _ = early.lost(IntegrationLoss::PostStartupFailure);
        assert!(!early.ever_qualified());
    }

    #[test]
    fn an_unqualified_replacement_is_visibly_terminal_only() {
        let mut gate = PhaseGate::unauthenticated();
        assert!(gate.authenticated(ShellKind::Bash));
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
    fn the_root_methods_are_the_registrys_own_group() {
        let names: Vec<&str> = root_methods()
            .iter()
            .map(|method| method.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "root.editor.enter",
                "root.editor.leave",
                "root.editor.fence",
                "root.eof.detach",
                "root.command.accepted",
            ]
        );
        for name in &names {
            assert!(is_root_method_name(name));
        }
        // The launch is authorised by the host and reaches the worker from a client, so it is not
        // in this group however closely it is bound to the same fence.
        assert!(!is_root_method_name("shell.launch"));
        assert!(!is_root_method_name("input.write"));
        // An unlisted name is not a method at all.
        assert!(!is_root_method_name("root.editor.something"));
    }

    #[test]
    fn a_degraded_session_does_not_recover_by_registering_again() {
        let mut gate = PhaseGate::unauthenticated();
        assert!(gate.authenticated(ShellKind::Fish));
        assert!(gate.qualified());
        assert!(
            !gate
                .lost(IntegrationLoss::BridgeDisconnected)
                .closes_session
        );
        assert_eq!(gate.phase(), IntegrationPhase::Degraded);
        assert!(!gate.authenticated(ShellKind::Fish));
        assert!(!gate.qualified());
        assert_eq!(gate.phase(), IntegrationPhase::Degraded);
        assert!(!gate.permits_launch());
    }
}
