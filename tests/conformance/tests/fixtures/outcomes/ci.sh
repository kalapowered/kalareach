#!/bin/sh
# The step that runs the ignored tests of this tree, naming each.
cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too \
  tests::is_ignored_for_a_reason_over_two_lines
