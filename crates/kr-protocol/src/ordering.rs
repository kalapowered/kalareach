//! The order a keystroke keeps with the requests sent on its connection.
//!
//! A client sends its keys, its viewport reports, its resizes and its reads on one connection. A
//! process that answers them in turn holds a key back for as long as a request ahead of it waits,
//! for the commits of a mutation or for a session another connection holds. Both the worker and the
//! control daemon therefore read a connection ahead while such a request runs and serve the keys
//! they find. This module is the one place that says which requests a key goes ahead of, and the
//! order the reading ahead keeps, so that the two processes cannot disagree.
//!
//! # What a key goes ahead of
//!
//! A key never goes ahead of an earlier key. It goes ahead of a read, and of a mutation that leaves
//! alone everything a key meets: the lease, the capabilities, the fence, the paste framing, which
//! attachments exist and the session's state. The geometry owner's size, who owns the size, whether
//! an attachment claims it and where an attachment's window is are such, so `terminal.resize`,
//! `terminal.geometry.transfer`, `attachment.configure` and `attachment.viewport` are. Every other
//! mutation, `session.open` (which scopes what the connection may reach), and every frame that is
//! not a request keep their place: a key sent after a detach is refused because the detach comes
//! first, and a frame that is new to the protocol blocks keys until someone has decided it does
//! not.
//!
//! # What a process adds
//!
//! The classification here is by method. A process maps its own frames to a [`Kind`] with
//! [`request_kind`] and [`mutation_kind`], and may make a frame [`Kind::Blocking`] that this module
//! calls independent: the control daemon does so for a frame it decides under another session or
//! grant than the connection acts under, because deciding it changes what ends the connection.
//! [`Sorting`] then keeps the order of what is read ahead.

use crate::authority::EffectClass;
use crate::method::Method;

/// How many frames are held that cannot be served before the connection is read no more.
pub const MOST_HELD: usize = 16;

/// What a frame is to the order a key keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An `input.write` sent as a request.
    Key,
    /// A frame a key goes ahead of: a read, and a mutation that leaves keys alone.
    Independent,
    /// Any other frame. A key does not go ahead of it.
    Blocking,
}

/// The kind of a request sent as a read: `method` is the method it names, `None` when the registry
/// does not know the name.
///
/// A method that is not a read, sent as a request, is refused before anything is decided, and so is
/// an unknown name; each is `Blocking`, so the order of what follows it is the one it was sent in.
#[must_use]
pub fn request_kind(method: Option<Method>) -> Kind {
    match method {
        Some(Method::InputWrite) => Kind::Key,
        Some(Method::SessionOpen) => Kind::Blocking,
        Some(method) if method.entry().effect == EffectClass::Read => Kind::Independent,
        _ => Kind::Blocking,
    }
}

/// The kind of a mutation: `method` is the method it names, `None` when the registry does not know
/// the name.
#[must_use]
pub fn mutation_kind(method: Option<Method>) -> Kind {
    match method {
        Some(method) if leaves_keys_alone(method) => Kind::Independent,
        _ => Kind::Blocking,
    }
}

/// Whether a mutation of `method` changes nothing a key meets.
///
/// A method that is not named is taken to be able to.
const fn leaves_keys_alone(method: Method) -> bool {
    matches!(
        method,
        Method::TerminalResize
            | Method::TerminalGeometryTransfer
            | Method::AttachmentConfigure
            | Method::AttachmentViewport
    )
}

/// What becomes of a frame that has been read ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// Serve it now.
    Serve,
    /// Hand it back, in its place.
    Defer,
}

/// The order the reading ahead keeps, as a function of the frames in the order they were sent.
#[derive(Debug, Default)]
pub struct Sorting {
    /// A frame that keys do not go ahead of has been held, so no key goes ahead now.
    blocked: bool,
    /// How many frames that cannot be served are held.
    held: usize,
}

impl Sorting {
    /// Decides what becomes of the next frame. `None` stands for a frame that could not be read or
    /// for the end of the stream.
    pub fn judge(&mut self, kind: Option<Kind>) -> Judgement {
        match kind {
            None | Some(Kind::Blocking) => {
                self.blocked = true;
                Judgement::Defer
            }
            Some(Kind::Key) if !self.blocked => Judgement::Serve,
            // A key is never served before an earlier key, so one held holds every key after it.
            Some(Kind::Key) => Judgement::Defer,
            Some(Kind::Independent) => {
                self.held += 1;
                Judgement::Defer
            }
        }
    }

    /// Whether the connection may be read for another frame: a key could still be served, and the
    /// frames held are few enough.
    #[must_use]
    pub const fn may_read(&self) -> bool {
        !self.blocked && self.held < MOST_HELD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decisions for `kinds`, in order, and whether the connection could still be read after
    /// each.
    fn judged(kinds: &[Option<Kind>]) -> Vec<(Judgement, bool)> {
        let mut sorting = Sorting::default();
        kinds
            .iter()
            .map(|kind| (sorting.judge(*kind), sorting.may_read()))
            .collect()
    }

    /// KR-PERF-002: a key goes ahead of a read and of a mutation that leaves keys alone, and of
    /// nothing else.
    #[test]
    fn a_key_goes_ahead_of_reads_and_geometry_and_of_nothing_else() {
        use Judgement::{Defer, Serve};
        let key = Some(request_kind(Some(Method::InputWrite)));
        let frames = [
            Some(request_kind(Some(Method::SessionRead))),
            Some(mutation_kind(Some(Method::AttachmentViewport))),
            Some(mutation_kind(Some(Method::TerminalResize))),
            key,
            Some(mutation_kind(Some(Method::SessionDetach))),
            key,
            Some(request_kind(Some(Method::SessionRead))),
            key,
        ];
        let decisions: Vec<_> = judged(&frames).into_iter().map(|(what, _)| what).collect();
        assert_eq!(
            decisions,
            [Defer, Defer, Defer, Serve, Defer, Defer, Defer, Defer],
            "a key is served ahead of the reads and the geometry before it, and held behind the \
             detach and behind the key held ahead of it"
        );
    }

    /// KR-PERF-002: the four geometry methods are independent of keys, `session.open` and a method
    /// the registry does not know are not, and a write sent as a request is not a read.
    #[test]
    fn the_method_rule_names_what_a_key_goes_ahead_of() {
        for method in [
            Method::TerminalResize,
            Method::TerminalGeometryTransfer,
            Method::AttachmentConfigure,
            Method::AttachmentViewport,
        ] {
            assert_eq!(mutation_kind(Some(method)), Kind::Independent, "{method}");
        }
        for method in [
            Method::SessionDetach,
            Method::SessionAttach,
            Method::InputAcquire,
            Method::SessionClose,
        ] {
            assert_eq!(mutation_kind(Some(method)), Kind::Blocking, "{method}");
        }
        assert_eq!(request_kind(Some(Method::InputWrite)), Kind::Key);
        assert_eq!(request_kind(Some(Method::SessionRead)), Kind::Independent);
        assert_eq!(request_kind(Some(Method::SessionOpen)), Kind::Blocking);
        assert_eq!(request_kind(Some(Method::SessionDetach)), Kind::Blocking);
        assert_eq!(request_kind(None), Kind::Blocking);
        assert_eq!(mutation_kind(None), Kind::Blocking);
    }

    /// KR-PERF-002: the connection is read for as long as a key could still be served, and for no
    /// more than the most frames that cannot be.
    #[test]
    fn the_connection_is_read_until_a_key_cannot_be_served_or_too_many_frames_are_held() {
        let reads = |count: usize| vec![Some(Kind::Independent); count];
        assert!(
            judged(&reads(MOST_HELD - 1))
                .last()
                .is_some_and(|(_, more)| *more)
        );
        assert!(
            judged(&reads(MOST_HELD))
                .last()
                .is_some_and(|(_, more)| !*more)
        );
        assert!(
            judged(&[Some(Kind::Blocking)])
                .last()
                .is_some_and(|(_, more)| !*more),
            "a frame a key does not go ahead of ends the reading"
        );
        assert!(
            judged(&[None]).last().is_some_and(|(_, more)| !*more),
            "so does a frame that could not be read"
        );
        // Keys served do not count against the frames held.
        let keys = vec![Some(Kind::Key); MOST_HELD * 2];
        assert!(
            judged(&keys)
                .iter()
                .all(|(what, more)| *what == Judgement::Serve && *more)
        );
    }
}
