#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
base_sha="${1:-}"
# Reviewed main baseline after the Phase 3C transition.
protocol_baseline=d89e88d8ae3e416563e4345fd653a10f67d89053
expected_buf="$(tr -d '\r\n' < .buf-version)"
if [[ "$(buf --version)" != "$expected_buf" ]]; then
  printf 'Expected Buf %s from .buf-version\n' "$expected_buf" >&2
  exit 1
fi
mkdir -p ci-artifacts
buf format --diff --exit-code 2>&1 | tee ci-artifacts/format.log
buf lint 2>&1 | tee ci-artifacts/lint.log
buf breaking --against ".git#ref=$protocol_baseline" 2>&1 | tee ci-artifacts/breaking.log
if [[ -n "$base_sha" && "$base_sha" != 0000000000000000000000000000000000000000 && "$base_sha" != "$protocol_baseline" ]]; then
  buf breaking --against ".git#ref=$base_sha" 2>&1 | tee -a ci-artifacts/breaking.log
fi
buf generate 2>&1 | tee ci-artifacts/generate.log
git diff --exit-code HEAD -- gen 2>&1 | tee ci-artifacts/generated-diff.log
untracked="$(git ls-files --others --exclude-standard -- gen)"
if [[ -n "$untracked" ]]; then
  printf 'Untracked generated files:\n%s\n' "$untracked" | tee -a ci-artifacts/generated-diff.log >&2
  exit 1
fi
