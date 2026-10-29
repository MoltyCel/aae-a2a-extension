#!/usr/bin/env bash
# Start the reference supplier and the reference buyer as two processes on
# localhost, run every cross-run case, and validate the result file.
#
#   scripts/crossrun-local.sh [result-file]
#
# Default result file: .crossrun/local.json (ignored by git). See CROSSRUN.md.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-.crossrun/local.json}"
PY="${VENV:-.venv}/bin/python"
[ -x "$PY" ] || make install >/dev/null

PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
URL="http://127.0.0.1:$PORT"
mkdir -p .crossrun
RECORD=".crossrun/supplier-decisions.jsonl"
: > "$RECORD"

"$PY" -m aae_a2a.crossrun serve --port "$PORT" --record "$RECORD" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  "$PY" -c "import httpx,sys; httpx.get('$URL/.well-known/agent-card.json').raise_for_status()" \
    2>/dev/null && break
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "supplier exited" >&2; exit 1; }
  sleep 0.1
done

"$PY" -m aae_a2a.crossrun client --url "$URL" --out "$OUT" \
  --participant "${CROSSRUN_PARTICIPANT:-local}"
echo
"$PY" -m aae_a2a.crossrun check "$OUT"
echo "supplier decisions: $(wc -l < "$RECORD" | tr -d ' ') lines in $RECORD"
