#!/usr/bin/env bash
# The daemon a shipped build makes, shown to refuse a plain-HTTP storage origin.
#
# A host whose `storage.origin` names a service that is not the managed account service holds an
# account at that service, and presents its account token there only over https. The rule that says
# so lets plain HTTP through only in a build with the `testing` feature, which this crate's own
# tests always compile in (the crate depends on itself with the feature for them), so no case that
# starts the daemon in-process can show what the program a person runs does.
#
# This builds that program alone, as `cargo build -p kr-controller --bin kr-controller` does, into
# a target directory of its own, so that no earlier build's features are the ones that run, and then
# runs the one case of the daemon's storage account suite that starts it over a document naming a
# plain-HTTP storage origin, once with a proxy and once without. The case shows a program that
# exits with a refusal naming `storage.origin` and has opened no connection to the origin or to the
# proxy, though a revocation that waited to be sent is kept for it to send.
#
# Usage: scripts/shipped-controller-gate.sh
#
# The build goes in a new directory under TMPDIR, removed when the run ends. KR_SHIPPED_TARGET_DIR
# names a directory to build in instead, and keeps it, for a run that is repeated.
#
# It exits 0 when the program refused both ways, and with the failing step's status otherwise.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ -n "${KR_SHIPPED_TARGET_DIR:-}" ]; then
  target="$KR_SHIPPED_TARGET_DIR"
  mkdir -p "$target"
else
  target="$(mktemp -d "${TMPDIR:-/tmp}/kr-shipped-controller.XXXXXX")"
  trap 'rm -rf "${target:?}"' EXIT
fi

CARGO_TARGET_DIR="$target" cargo build --locked -p kr-controller --bin kr-controller
KR_SHIPPED_CONTROLLER="$target/debug/kr-controller" cargo test --locked -p kr-controller --test storage_account -- --ignored --exact a_shipped_controller_refuses_a_plain_http_storage_origin_before_it_sends_anything --nocapture
