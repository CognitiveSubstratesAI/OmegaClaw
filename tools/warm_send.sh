#!/bin/bash
# warm_send.sh — send a Julia snippet to the persistent warm session, print its output, and
# EXIT WITH THE SNIPPET'S STATUS.
# Usage:  tools/warm_send.sh snippet.jl     |     echo 'CODE' | tools/warm_send.sh
# Exit:   0 = snippet completed · 1 = snippet threw (test failure/error) · 2 = timeout · 3 = no session
#
# TWO SILENT-SUCCESS BUGS FIXED 2026-07-23 — both hid failures, both cost real time:
#
#  1. EXIT-CODE BLINDNESS. This script used to `cat out.txt` and exit 0 unconditionally, while
#     `warm_session.jl` caught the snippet's exception into out.txt. So A FAILING TEST SUITE
#     REPORTED SUCCESS to any caller. Verified: a testset containing `@test 1 == 2` exits 0 through
#     the old path and 1 under plain `julia file.jl`. Every "green" warm result was therefore read
#     off PRINTED TEXT, never a status — workable for a human reading carefully, worthless for
#     automation, and exactly how a dead oracle sits unnoticed (MORK's upstream differential errored
#     on every run for an unknown length of time). The session now writes `.warm/status` ("0"/"1")
#     BEFORE `.warm/done`; we exit with it. A MISSING status is treated as FAILURE, never success.
#
#  2. STALE OUTPUT ON TIMEOUT. On timeout it printed the PREVIOUS run's out.txt with no indication,
#     so a slow job looked like a failed one showing yesterday's error. Three separate misdiagnoses
#     in one session traced to this. Now: a loud banner, NO stale output, exit 2 (distinct from a
#     genuine snippet failure, which is 1). Default wait raised 120s -> 600s, since full suites
#     legitimately exceed two minutes and were being reported as failures.
set -uo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)/.warm"
[ -f "$DIR/ready" ] || {
  echo "warm session not running — start:" >&2
  echo "  systemd-run --user --unit=core-warm --working-directory=\$PWD \$(which julia) --project=. tools/warm_session.jl" >&2
  echo "  # allow-cold-start: warm session startup" >&2
  exit 3
}

SEQ=$(( $(cat "$DIR/seq" 2>/dev/null || echo 0) + 1 ))
cat "${1:-/dev/stdin}" > "$DIR/in.jl"
rm -f "$DIR/status"                       # never inherit the previous run's verdict
echo "$SEQ" > "$DIR/seq"

TIMEOUT_S="${WARM_TIMEOUT_S:-600}"
deadline=$(( $(date +%s) + TIMEOUT_S ))
while [ "$(cat "$DIR/done" 2>/dev/null)" != "$SEQ" ]; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "=== warm_send.sh: TIMEOUT after ${TIMEOUT_S}s waiting for seq=$SEQ ===" >&2
    echo "=== the job may STILL BE RUNNING. Output NOT printed (it would be the PREVIOUS run's)." >&2
    echo "=== poll:  [ \"\$(cat $DIR/done)\" = \"$SEQ\" ]   then read $DIR/out.txt" >&2
    exit 2
  fi
  sleep 0.2
done

cat "$DIR/out.txt"
exit "$(cat "$DIR/status" 2>/dev/null || echo 1)"    # missing status ⇒ assume FAILURE
