#!/usr/bin/env bash
# Da a WhiteWidow Net el ÚNICO permiso que necesita para escuchar la red: cap_net_raw (leer paquetes).
# Se hace sobre una COPIA del Python dentro de .venv (python-ww): no se modifica el Python del sistema,
# la app sigue corriendo como tu usuario (no root) y solo el proceso de escucha usa esa copia.
# Pide sudo una vez. Revertir: ./scripts/enable-sniffer.sh --disable
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
source scripts/common.sh
VENV_PY="$WW_DIR/.venv/bin/python-ww"
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"
[ -x "$WW_DIR/.venv/bin/python3" ] || die "Primero ejecuta ./install.sh"
if [ "${1:-}" = "--disable" ]; then rm -f "$VENV_PY"; say "Escucha pasiva desactivada (permiso retirado)."; exit 0; fi
if ! command -v setcap >/dev/null; then
  say "Instalando libcap2-bin (para setcap)..."; $SUDO apt-get install -y libcap2-bin
fi
cp -f "$(readlink -f "$WW_DIR/.venv/bin/python3")" "$VENV_PY"
chmod 755 "$VENV_PY"
say "Concediendo cap_net_raw a $VENV_PY (se pedirá tu contraseña de sudo)"
$SUDO setcap cap_net_raw=eip "$VENV_PY"
# Verifica como un usuario SIN privilegios (si se ejecuta como root, un chequeo como root siempre pasaría)
CHECK='import socket; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)); s.close()'
if [ "$(id -u)" -eq 0 ]; then
  U="${SUDO_USER:-nobody}"
  if command -v runuser >/dev/null; then ok=0; runuser -u "$U" -- "$VENV_PY" -c "$CHECK" 2>/dev/null && ok=1; else ok=1; fi
else
  ok=0; "$VENV_PY" -c "$CHECK" 2>/dev/null && ok=1
fi
if [ "$ok" -eq 1 ]; then
  say "Listo: la escucha pasiva está habilitada. Reinicia con ./stop.sh && ./start.sh"
else
  rm -f "$VENV_PY"
  die "El permiso no tuvo efecto: este sistema o sistema de archivos no aplica capabilities de archivo. La escucha pasiva no estará disponible."
fi
