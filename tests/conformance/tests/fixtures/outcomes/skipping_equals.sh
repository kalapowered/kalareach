#!/bin/sh
# A command that names every test and then leaves one of them out, in the one-word form of the flag.
cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines --skip=tests::is_ignored_too
