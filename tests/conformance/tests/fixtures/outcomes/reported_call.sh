#!/bin/sh
# A command whose calls name two of the tests, and a line that begins with another word and holds the
# call's words and the third test.
run() { cargo test --lib -- --ignored --exact "$1"; }
call tests::is_ignored
fail "call tests::is_ignored_too did not run"
call tests::is_ignored_for_a_reason_over_two_lines
