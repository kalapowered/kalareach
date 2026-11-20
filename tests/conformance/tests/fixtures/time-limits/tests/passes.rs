// A test that passes, so a step with a time limit that ends in time is read as one without. When a
// case sets `KR_RUN_SECONDS` it waits that long first, with `sleep`, and records its pid in the file
// `KR_BLOCK_PIDS` names: the step's run is then a command that takes time.
#[test]
fn a_test_that_passes() {
    let Some(seconds) = std::env::var("KR_RUN_SECONDS")
        .ok()
        .and_then(|text| text.parse().ok())
    else {
        return;
    };
    if let Ok(file) = std::env::var("KR_BLOCK_PIDS") {
        std::fs::write(file, format!("{}\n", std::process::id())).expect("the pid file");
    }
    std::thread::sleep(std::time::Duration::from_secs(seconds));
}
