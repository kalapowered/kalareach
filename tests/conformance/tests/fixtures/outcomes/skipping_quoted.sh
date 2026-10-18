#!/bin/sh
# A command that names every test and leaves one out with the flag in quotes.
cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines "--skip=tests::is_ignored_too"
