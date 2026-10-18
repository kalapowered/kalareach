#!/bin/sh
# A command whose calls name two of the tests, and a line that only says the third.
run() { cargo test --lib -- --ignored --exact "$1"; }
call tests::is_ignored
echo tests::is_ignored_too
call tests::is_ignored_for_a_reason_over_two_lines
