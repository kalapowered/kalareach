#!/bin/sh
# The only line with the command's words begins with echo: it says them and runs nothing.
echo cargo test --lib -- --ignored --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines
