//! The product's own messages whose exact words are fixed.

use kr_boundary_windows::messages;

#[test]
fn the_installers_wait_and_the_brokers_answer_say_these_words() {
    assert_eq!(
        messages::APPLICATION_CONTROL_STARTING,
        "Windows starts application control after the service starts, and the installation waits for it."
    );
    assert_eq!(
        messages::STILL_STARTING,
        "Windows is still starting application control after the restart; try again in a few minutes."
    );
}
