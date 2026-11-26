#!/usr/bin/env bash
# Detiene WhiteWidow Net (al detenerse genera un informe final en ~/.local/share/whitewidow-net/reports).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
source scripts/common.sh
if ! ww_running; then say "No está en ejecución."; rm -f "$WW_PID"; exit 0; fi
PID="$(cat "$WW_PID")"; kill -TERM "$PID"
for _ in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || { rm -f "$WW_PID"; say "Detenido."; exit 0; }; sleep 0.5; done
warn "No respondió a SIGTERM; forzando."; kill -KILL "$PID" 2>/dev/null || true; rm -f "$WW_PID"; say "Detenido."
