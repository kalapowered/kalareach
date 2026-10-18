#!/bin/sh
# A command that names every test, passes a variable, and then leaves one test out.
cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines "$extra" --skip tests::is_ignored_too
