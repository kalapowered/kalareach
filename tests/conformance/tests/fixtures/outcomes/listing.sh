#!/bin/sh
# A command that lists the ignored tests and runs none of them.
cargo test --lib -- --ignored --list
