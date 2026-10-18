#!/bin/sh
# A command that selects the ignored tests by a part of their names, and a part none of them holds.
cargo test --lib -- --ignored no_such_case
