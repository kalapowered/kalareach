#!/bin/sh
# A command that selects the ignored tests by a part of their names, put before the arguments of the
# test program, and a part none of them holds.
cargo test -p outcomes --lib no_such_case -- --ignored
