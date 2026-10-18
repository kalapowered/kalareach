#!/bin/sh
# A command that takes the test's name from the call that runs it.
run() { cargo test --lib -- --ignored --exact "$1"; }
call tests::is_ignored
call tests::is_ignored_too
call tests::is_ignored_for_a_reason_over_two_lines
