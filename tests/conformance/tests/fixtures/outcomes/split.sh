#!/bin/sh
# The names of the tests are on a line of their own, a separate command from the one that selects.
cargo test --lib -- --ignored --exact
tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines
