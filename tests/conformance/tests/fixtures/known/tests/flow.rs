//! KR-REQ-07.01: both tests of this file.

/// Records a known difference the way the application matrix does.
fn record(test: &str) {
    use std::io::Write;
    let Some(directory) = std::env::var_os("KR_TEST_ARTIFACTS_DIR") else {
        return;
    };
    let path = std::path::Path::new(&directory).join("known-differences.jsonl");
    let line = format!(
        "{{\"package\":\"known\",\"target\":\"flow\",\"test\":\"{test}\",\"subject\":\"a sequence\",\
         \"application\":\"two cells\",\"grid\":\"four cells\",\"observed\":\"a row\"}}\n"
    );
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .expect("records the difference");
}

/// KR-REQ-07.02: what the profile defines holds, and an application reads it otherwise.
#[test]
fn holds_what_the_profile_defines() {
    record("holds_what_the_profile_defines");
}

#[test]
fn an_ordinary_pass() {}
