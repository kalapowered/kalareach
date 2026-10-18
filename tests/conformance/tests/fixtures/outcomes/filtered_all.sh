#!/bin/sh
# A command that selects the ignored tests by a part of their names that every one of them holds.
cargo test --lib -- --ignored is_ignored --test-threads 1
