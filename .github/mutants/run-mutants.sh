#!/bin/bash
# run-mutants.sh <id>...: for each named mutation, builds the store's tests from the mutated text and runs the cases of the
# in-place switch and the loop case, and says what happened: killed (a case failed), limit (the run was ended by its
# limit), not built (the mutated text did not compile) or survived (every case passed). A control run of the same cases
# at the unmutated text comes first and must pass.
CASES=(a_reader_that_holds_current_open a_switch_that_ends_at_any_moment a_current_that_is_a_plain_directory a_name_put_in_the_place_of_current current_names_a_whole_release_at_every_moment_of_a_switch)

echo "MUTANT-CONTROL building"
if ! cargo test --locked -p kr-ipc --test install --no-run > control-build.log 2>&1; then
  echo "MUTANT-CONTROL not built"
  exit 1
fi
if timeout 900 cargo test --locked -p kr-ipc --test install -- "${CASES[@]}" > control-run.log 2>&1; then
  echo "MUTANT-CONTROL passed: $(grep -E '^test result' control-run.log | head -1)"
else
  echo "MUTANT-CONTROL failed"
  grep -E 'FAILED|panicked' control-run.log | head -5
  exit 1
fi

for id in "$@"; do
  git checkout -q -- crates
  if ! python .github/mutants/mutate.py "$id"; then
    echo "MUTANT $id: mutation text missing"
    continue
  fi
  if ! cargo test --locked -p kr-ipc --test install --no-run > "build-$id.log" 2>&1; then
    echo "MUTANT $id: not built: $(grep -m1 -E '^error' "build-$id.log" | cut -c1-160)"
    continue
  fi
  timeout 900 cargo test --locked -p kr-ipc --test install -- "${CASES[@]}" > "run-$id.log" 2>&1
  code=$?
  if [ "$code" -eq 124 ]; then
    echo "MUTANT $id: ended by its limit"
  elif [ "$code" -eq 0 ]; then
    echo "MUTANT $id: survived: $(grep -E '^test result' "run-$id.log" | head -1)"
  else
    echo "MUTANT $id: killed (exit $code) by: $(grep -E '^test .* FAILED' "run-$id.log" | sed 's/^test //; s/ \.\.\. FAILED//' | tr '\n' ' ')"
  fi
done
git checkout -q -- crates
