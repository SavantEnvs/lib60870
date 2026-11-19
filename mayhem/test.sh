#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's Unity suite (lib60870-C/tests/all_tests.c, 94 tests in this configuration: ASDU/information-object
# encode+decode known-answer tests, CS104 client/server over loopback TCP, queues, file service),
# built by build.sh into mayhem/out/tests/all_tests. Unity prints one line per test
# ("file:line:name:PASS|FAIL|IGNORE") and a summary "N Tests F Failures I Ignored".
RUNNER="$SRC/mayhem/out/tests/all_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh must build it" >&2
  emit_ctrf "unity" 0 1 0
  exit 1
fi
LOG="$(mktemp)"
( cd "$(mktemp -d)" && "$RUNNER" ) >"$LOG" 2>&1
rc=$?
tail -n 5 "$LOG"
grep -E ':FAIL' "$LOG" | head -20
passed=$(grep -cE ':PASS$' "$LOG" || true)
failed=$(grep -cE ':FAIL' "$LOG" || true)
skipped=$(grep -cE ':IGNORE' "$LOG" || true)
summary=$(grep -E '^[0-9]+ Tests [0-9]+ Failures [0-9]+ Ignored' "$LOG" | tail -1)
rm -f "$LOG"
# A run that did not reach Unity's summary (crash, abort, no-op binary) is a failure, as is a
# summary whose total disagrees with the per-test lines.
if [ -z "$summary" ]; then
  echo "test.sh: no Unity summary (runner exit $rc)" >&2
  failed=$((failed + 1))
else
  total=$(echo "$summary" | awk '{print $1}')
  if [ "$total" -ne $((passed + failed + skipped)) ] || [ "$total" -lt 90 ]; then
    echo "test.sh: Unity summary '$summary' disagrees with per-test results" >&2
    failed=$((failed + 1))
  fi
fi
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
emit_ctrf "unity" "$passed" "$failed" "$skipped"
