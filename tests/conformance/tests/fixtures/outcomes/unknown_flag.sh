#!/bin/sh
# A command with a flag of the test program that the map does not know to leave every test running.
cargo test --lib -- --ignored --unstable-options
