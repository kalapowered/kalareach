#!/bin/sh
# A step whose arguments end where a comment begins: what follows the comment sign does not run,
# in quotes opened on the line before it as well.
if ! output="$(cargo test --lib -- --ignored \
  # --exact tests::is_ignored tests::is_ignored_too tests::is_ignored_for_a_reason_over_two_lines
  )"; then exit 1; fi
