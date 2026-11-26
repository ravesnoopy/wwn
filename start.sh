#!/usr/bin/env bash
# Inicia WhiteWidow Net en segundo plano y abre el dashboard. Opciones: --no-browser, --token, --lan (escuchar en la red local)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
source scripts/common.sh
BROWSER=1; SHOWTOKEN=0; EXTRA=()
for a in "$@"; do case "$a" in --no-browser) BROWSER=0;; --token) SHOWTOKEN=1;; --lan) EXTRA+=(--host 0.0.0.0);; *) die "Opción desconocida: $a";; esac; done
[ -x "$WW_PY" ] || die "No está instalado. Ejecuta ./install.sh primero."
export PYTHONPATH="$WW_DIR"
if ww_running; then say "Ya está en ejecución (PID $(cat "$WW_PID"))."
else
  [ "${#EXTRA[@]}" -eq 0 ] || warn "Modo --lan: el dashboard será visible para toda la red local. Nunca lo expongas a Internet."
  nohup "$WW_PY" -m whitewidow_net serve "${EXTRA[@]}" >> "$WW_LOG" 2>&1 &
  echo $! > "$WW_PID"
  PORT="$(ww_port)"
  for _ in $(seq 1 30); do
    "$WW_PY" -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:$PORT/api/health',timeout=1)" >/dev/null 2>&1 && break
    kill -0 "$(cat "$WW_PID")" 2>/dev/null || { rm -f "$WW_PID"; die "El servicio no arrancó. Revisa $WW_LOG"; }
    sleep 0.5
  done
  say "Servicio iniciado (PID $(cat "$WW_PID"))."
fi
PORT="$(ww_port)"; URL="http://127.0.0.1:$PORT"
say "Dashboard: $URL"
if [ "$SHOWTOKEN" -eq 1 ]; then "$WW_PY" -m whitewidow_net token; fi
if [ "$BROWSER" -eq 1 ] && [ -n "${DISPLAY:-${WAYLAND_DISPLAY:-}}" ] && command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1 || true; fi
