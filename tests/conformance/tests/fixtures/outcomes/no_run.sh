#!/bin/sh
# A command that builds the tests and runs none of them.
cargo test --lib --no-run -- --ignored
