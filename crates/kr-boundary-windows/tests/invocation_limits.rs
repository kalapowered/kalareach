//! What the broker counts before it does any work for a request: the invocations one account has
//! running and the invocations the whole computer has running. A request over either limit is
//! refused with the kind `limit`, and a refused request leaves nothing counted.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use kr_boundary_windows::frame::invocation::RefusedKind;
use kr_boundary_windows::limits::{
    InvocationCounts, MAX_INVOCATIONS_PER_CLIENT, MAX_INVOCATIONS_PER_MACHINE, RULE_PER_CLIENT,
    RULE_PER_MACHINE,
};

/// An account's identifier, as the broker keys its counts.
fn person(number: usize) -> String {
    format!("S-1-5-21-1-2-3-{}", 1000 + number)
}

#[test]
fn one_account_gets_its_limit_and_no_more() {
    let counts = InvocationCounts::new();
    let held: Vec<_> = (0..MAX_INVOCATIONS_PER_CLIENT)
        .map(|_| counts.admit(&person(1)).expect("within the limit"))
        .collect();
    let refusal = counts.admit(&person(1)).expect_err("one over the limit");
    assert_eq!(refusal.kind, RefusedKind::Limit);
    assert_eq!(refusal.rule, RULE_PER_CLIENT);
    assert_eq!(counts.in_use(), held.len(), "the refusal counted nothing");
}

#[test]
fn the_computer_gets_its_limit_whoever_asks() {
    let counts = InvocationCounts::new();
    let mut held = Vec::new();
    let mut asker = 0;
    while held.len() < MAX_INVOCATIONS_PER_MACHINE {
        held.push(counts.admit(&person(asker)).expect("within both limits"));
        asker += 1;
    }
    let refusal = counts
        .admit(&person(asker))
        .expect_err("one over the computer's limit, from an account with none running");
    assert_eq!(refusal.kind, RefusedKind::Limit);
    assert_eq!(refusal.rule, RULE_PER_MACHINE);
    assert_eq!(counts.in_use(), MAX_INVOCATIONS_PER_MACHINE);
}

#[test]
fn an_account_at_its_limit_is_told_so_and_not_that_the_computer_is_full() {
    let counts = InvocationCounts::new();
    let _held: Vec<_> = (0..MAX_INVOCATIONS_PER_CLIENT)
        .map(|_| counts.admit(&person(1)).expect("within the limit"))
        .collect();
    assert_eq!(counts.admit(&person(1)).unwrap_err().rule, RULE_PER_CLIENT);
    assert!(
        counts.admit(&person(2)).is_ok(),
        "another account is not held off by the first one's limit"
    );
}

#[test]
fn a_permit_that_ends_gives_its_place_back_and_only_its_own() {
    let counts = InvocationCounts::new();
    let first = counts.admit(&person(1)).unwrap();
    let _second = counts.admit(&person(1)).unwrap();
    assert!(counts.admit(&person(1)).is_err());
    drop(first);
    let _third = counts
        .admit(&person(1))
        .expect("the place of the ended invocation is free");
    assert!(counts.admit(&person(1)).is_err());
    assert_eq!(counts.in_use(), MAX_INVOCATIONS_PER_CLIENT);
}

#[test]
fn a_thread_that_panics_with_a_permit_gives_its_place_back() {
    let counts = InvocationCounts::new();
    let for_thread = Arc::clone(&counts);
    let ended = std::thread::spawn(move || {
        let _permit = for_thread.admit(&person(1)).unwrap();
        panic!("the invocation's thread fails");
    })
    .join();
    assert!(ended.is_err());
    assert_eq!(counts.in_use(), 0);
    assert!(counts.admit(&person(1)).is_ok());
}

#[test]
fn threads_that_ask_together_never_hold_more_than_the_limits() {
    let counts = InvocationCounts::new();
    let asking = MAX_INVOCATIONS_PER_MACHINE * 4;
    let start = Arc::new(Barrier::new(asking));
    let admitted = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..asking)
        .map(|number| {
            let counts = Arc::clone(&counts);
            let start = Arc::clone(&start);
            let admitted = Arc::clone(&admitted);
            std::thread::spawn(move || {
                start.wait();
                // Each account asks twice from two threads, so the accounts' limits are met too.
                let permit = counts.admit(&person(number / 2));
                if permit.is_ok() {
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
                // The place is held until every thread has asked.
                start.wait();
                permit.is_ok()
            })
        })
        .collect();
    let granted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|granted| *granted)
        .count();
    assert_eq!(granted, admitted.load(Ordering::SeqCst));
    assert_eq!(
        granted, MAX_INVOCATIONS_PER_MACHINE,
        "every place the computer has was taken, and none beyond"
    );
    assert_eq!(counts.in_use(), 0, "every permit was given back");
}

#[test]
fn the_limits_are_ordered_so_that_one_account_cannot_take_the_whole_computer_alone() {
    assert!(MAX_INVOCATIONS_PER_CLIENT >= 1);
    assert!(MAX_INVOCATIONS_PER_CLIENT < MAX_INVOCATIONS_PER_MACHINE);
}
