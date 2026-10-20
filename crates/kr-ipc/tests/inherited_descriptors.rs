//! What a program this process starts is handed of the descriptors the endpoint code opens.
//!
//! macOS has no flag to open a socket close-on-exec, so a program another thread starts between
//! the socket call and the call that marks it inherits the socket there, and no code can prevent
//! that. These cases run where the socket is marked as it is made.

#![cfg(all(unix, not(target_vendor = "apple")))]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_ipc::endpoint::Listener;
use kr_ipc::testing::{TempHost, descriptors_a_started_program_holds};

/// How many programs are started at most while the endpoint is probed over and over. The probe
/// holds its socket for a few system calls in every few, so a probe that leaks it is caught within
/// a handful of starts; the rest is margin.
const STARTS: usize = 400;

/// A program started while an endpoint is being probed for a listener is not handed the probe's
/// socket. The probe is the descriptor `Listener::bind` opens to learn whether an address is
/// taken, and a child that held it would keep a connection to the live listener open for as long as
/// the child ran.
#[test]
fn a_program_started_while_an_endpoint_is_probed_is_not_handed_the_probes_socket() {
    let tree = TempHost::create();
    let endpoint = tree
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let _entered = runtime.enter();
    let live = Listener::bind(&endpoint).expect("a live listener");
    let baseline = descriptors_a_started_program_holds();

    // Another thread asks again and again for the address the listener holds, and is told it is
    // taken: each ask opens the probe's socket and closes it a moment later.
    let stop = Arc::new(AtomicBool::new(false));
    let probing = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let endpoint = endpoint.clone();
        move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            let _entered = runtime.enter();
            while !stop.load(Ordering::Relaxed) {
                assert!(Listener::bind(&endpoint).is_err(), "the address is taken");
            }
        }
    });
    let mut handed = Vec::new();
    for _ in 0..STARTS {
        handed = descriptors_a_started_program_holds()
            .difference(&baseline)
            .copied()
            .collect();
        if !handed.is_empty() {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    probing.join().expect("the probing thread ends");
    drop(live);
    assert!(
        handed.is_empty(),
        "a program started during a probe was handed descriptors {handed:?}"
    );
}
