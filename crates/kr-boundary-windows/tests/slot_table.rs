//! The slot table: one operation at a time on a tree, by the identity of its directories. The cases
//! use real file keys and no machine, so they run on every platform.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::lifecycle::{
    BUSY_WORDS, LEFTOVER_WORDS, RULE_BUSY, RULE_LEFTOVER, RULE_UNCERTAIN, UNCERTAIN_END_WORDS,
};
use kr_boundary_windows::slot::{Blocked, SlotGuard, SlotTable, TreeIdentity};

const VOLUME: u64 = 0xA1B2_C3D4;

fn chain(volume: u64, references: &[u64]) -> TreeIdentity {
    TreeIdentity {
        chain: references
            .iter()
            .map(|reference| FileKey::ntfs(volume, *reference))
            .collect(),
    }
}

#[test]
fn slot_table_a_tree_is_busy_while_another_operation_holds_it() {
    let table = SlotTable::new();
    let tree = chain(VOLUME, &[5, 40, 77]);
    let guard = table
        .try_acquire(&tree)
        .expect("the first request takes it");
    let refusal = table
        .try_acquire(&tree)
        .expect_err("the second request for the tree is refused");
    assert_eq!(refusal.rule, RULE_BUSY);
    assert_eq!(refusal.detail(), BUSY_WORDS);
    guard.free_after_clean_release();
    assert!(table.is_empty(), "a freed slot leaves no row");
    table
        .try_acquire(&tree)
        .expect("the tree is free after a clean release");
}

#[test]
fn slot_table_two_trees_overlap_when_one_chain_is_a_prefix_of_the_other() {
    let table = SlotTable::new();
    let outer = chain(VOLUME, &[5, 40]);
    let inner = chain(VOLUME, &[5, 40, 77, 91]);
    let outer_guard = table.try_acquire(&outer).expect("the outer tree is taken");
    let refusal = table
        .try_acquire(&inner)
        .expect_err("a tree inside a held tree is refused");
    assert_eq!(refusal.rule, RULE_BUSY, "inside");
    outer_guard.free_after_clean_release();
    let inner_guard = table.try_acquire(&inner).expect("the inner tree is taken");
    let refusal = table
        .try_acquire(&outer)
        .expect_err("the tree around a held tree is refused");
    assert_eq!(refusal.rule, RULE_BUSY, "around");
    inner_guard.free_after_clean_release();
    assert!(table.is_empty());
}

#[test]
fn slot_table_trees_on_other_volumes_or_beside_each_other_do_not_overlap() {
    let table = SlotTable::new();
    let first = chain(VOLUME, &[5, 40, 77]);
    let beside = chain(VOLUME, &[5, 40, 78]);
    let other_volume = chain(VOLUME + 1, &[5, 40, 77]);
    let _first = table.try_acquire(&first).expect("the first tree is taken");
    let _beside = table
        .try_acquire(&beside)
        .expect("a tree beside it, with the same parent, is taken");
    let _other = table
        .try_acquire(&other_volume)
        .expect("the same references on another volume are other directories");
    // Two siblings where the name of one begins with the name of the other (`proj` and `proj2`),
    // and a tree whose chain begins with the digits of another's, are not nested: a chain is read
    // key by key, never as text.
    let proj = chain(VOLUME, &[5, 40, 7]);
    let _proj = table
        .try_acquire(&proj)
        .expect("a sibling whose reference is the start of another's as text is taken");
    let digits = chain(VOLUME, &[5, 4]);
    let _digits = table
        .try_acquire(&digits)
        .expect("a tree whose chain is the start of another's as text is taken");
    assert_eq!(table.len(), 5);
}

#[test]
fn slot_table_a_slot_kept_blocked_refuses_by_its_reason_until_it_is_freed() {
    let table = SlotTable::new();
    let tree = chain(VOLUME, &[5, 40, 77]);
    let nested = chain(VOLUME, &[5, 40, 77, 91]);
    let around = chain(VOLUME, &[5, 40]);
    table
        .try_acquire(&tree)
        .expect("taken")
        .keep(Blocked::Leftover("the hooks folder".to_owned()), None);
    for (what, other) in [
        ("the tree", &tree),
        ("inside", &nested),
        ("around", &around),
    ] {
        let refusal = table
            .try_acquire(other)
            .expect_err("a tree that overlaps a leftover is refused");
        assert_eq!(refusal.rule, RULE_LEFTOVER, "{what}");
        assert_eq!(
            refusal.detail(),
            format!("{LEFTOVER_WORDS}: the hooks folder"),
            "{what}"
        );
    }
    // Recovery reaches the row by its chain, and a clean end of that work opens it.
    table
        .reserve(&tree, Blocked::Uncertain)
        .keep(Blocked::Uncertain, None);
    let refusal = table
        .try_acquire(&nested)
        .expect_err("closed as not proved");
    assert_eq!(refusal.rule, RULE_UNCERTAIN);
    assert_eq!(refusal.detail(), UNCERTAIN_END_WORDS);
    table
        .reserve(&tree, Blocked::Uncertain)
        .free_after_clean_release();
    assert!(table.is_empty(), "the one row is freed");
    table.try_acquire(&nested).expect("free after the release");
}

#[test]
fn slot_table_a_leftover_is_named_before_an_end_not_proved_before_a_running_operation() {
    let table = SlotTable::new();
    let outer = chain(VOLUME, &[5, 40]);
    let busy = chain(VOLUME, &[5, 40, 1]);
    let uncertain = chain(VOLUME, &[5, 40, 2]);
    let left = chain(VOLUME, &[5, 40, 3]);
    let probe = chain(VOLUME, &[5, 40, 9]);
    let _busy = table.try_acquire(&busy).expect("taken");
    drop(table.reserve(&uncertain, Blocked::Uncertain));
    // The probe lies beside the three, so nothing overlaps it; the outer tree overlaps all.
    table.try_acquire(&probe).expect("beside them, free");
    assert_eq!(
        table.try_acquire(&outer).expect_err("refused").rule,
        RULE_UNCERTAIN
    );
    drop(table.reserve(&left, Blocked::Leftover("a file".to_owned())));
    assert_eq!(
        table.try_acquire(&outer).expect_err("refused").rule,
        RULE_LEFTOVER
    );
}

#[test]
fn slot_table_a_dropped_slot_stays_closed_as_an_end_not_proved() {
    let table = SlotTable::new();
    let tree = chain(VOLUME, &[5, 40, 77]);
    drop(table.try_acquire(&tree).expect("taken"));
    let refusal = table
        .try_acquire(&tree)
        .expect_err("a slot that was dropped is not free");
    assert_eq!(refusal.rule, RULE_UNCERTAIN);
}

#[test]
fn slot_table_a_reserved_chain_is_reserved_once_however_often_it_is_reserved() {
    let table = SlotTable::new();
    let tree = chain(VOLUME, &[5, 40, 77]);
    let first = table.reserve(&tree, Blocked::Uncertain);
    let second = table.reserve(&tree, Blocked::Leftover("a file".to_owned()));
    assert_eq!(table.len(), 1, "one row for one chain");
    let refusal = table.try_acquire(&tree).expect_err("closed");
    assert_eq!(refusal.rule, RULE_LEFTOVER, "the later reason stands");
    drop(first);
    drop(second);
    assert_eq!(
        table.len(),
        1,
        "a reserved row stays closed when its guards go"
    );
    assert_eq!(
        table.try_acquire(&tree).expect_err("closed").rule,
        RULE_LEFTOVER,
        "and keeps its reason"
    );
}

const THREADS: usize = 24;

/// Starts one thread for each identity, all released at once, and says which of them got a slot.
fn race(table: &SlotTable, identities: Vec<TreeIdentity>) -> Vec<Option<SlotGuard>> {
    let barrier = Arc::new(Barrier::new(identities.len()));
    let handles: Vec<_> = identities
        .into_iter()
        .map(|identity| {
            let table = table.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                match table.try_acquire(&identity) {
                    Ok(guard) => Some(guard),
                    Err(refusal) => {
                        assert_eq!(refusal.rule, RULE_BUSY);
                        None
                    }
                }
            })
        })
        .collect();
    handles
        .into_iter()
        .map(|handle| handle.join().expect("a thread ends"))
        .collect()
}

#[test]
fn slot_table_of_many_threads_that_acquire_one_tree_one_wins() {
    let table = SlotTable::new();
    let tree = chain(VOLUME, &[5, 40, 77]);
    for round in 0..50 {
        let held = race(&table, vec![tree.clone(); THREADS]);
        assert_eq!(
            held.iter().flatten().count(),
            1,
            "round {round}: one winner"
        );
        for guard in held.into_iter().flatten() {
            guard.free_after_clean_release();
        }
        assert!(table.is_empty());
    }
}

#[test]
fn slot_table_of_many_threads_that_acquire_a_tree_and_the_trees_inside_it_never_both_win() {
    let table = SlotTable::new();
    let outer = chain(VOLUME, &[5, 40]);
    for round in 0..50 {
        let mut identities = vec![outer.clone()];
        identities.extend((1..THREADS as u64).map(|number| chain(VOLUME, &[5, 40, number])));
        let held = race(&table, identities);
        let outer_won = held[0].is_some();
        let inside = held[1..].iter().flatten().count();
        // The trees inside do not overlap each other. Either the outer tree won and every tree
        // inside was refused, or one of them came first and the outer tree was refused.
        if outer_won {
            assert_eq!(inside, 0, "round {round}: the outer tree won alone");
        } else {
            assert_eq!(inside, THREADS - 1, "round {round}: the trees inside won");
        }
        for guard in held.into_iter().flatten() {
            guard.free_after_clean_release();
        }
        assert!(table.is_empty());
    }
}

#[test]
fn slot_table_a_hold_kept_with_a_blocked_slot_is_let_go_when_the_slot_is_freed() {
    struct Hold(Arc<AtomicBool>);
    impl Drop for Hold {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let table = SlotTable::new();
    let tree = chain(VOLUME, &[5, 40, 77]);
    let dropped = Arc::new(AtomicBool::new(false));
    table.try_acquire(&tree).expect("taken").keep(
        Blocked::Uncertain,
        Some(Box::new(Hold(Arc::clone(&dropped)))),
    );
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the handles stay held while the slot is closed"
    );
    table
        .reserve(&tree, Blocked::Uncertain)
        .free_after_clean_release();
    assert!(
        dropped.load(Ordering::SeqCst),
        "the handles are let go with the slot"
    );
}
