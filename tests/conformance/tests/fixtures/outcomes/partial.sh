#!/bin/sh
# A step that names one of the ignored tests of this tree and asks for them by name.
cargo test --lib -- --ignored --exact tests::is_ignored
