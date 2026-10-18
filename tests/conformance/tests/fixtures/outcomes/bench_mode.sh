#!/bin/sh
# A command that puts the test program in its benchmark mode, which runs no test.
cargo test --lib -- --ignored --bench
