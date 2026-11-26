#!/usr/bin/env bash
# Desinstala WhiteWidow Net. Por defecto conserva tus datos e informes; usa --purge para borrarlos.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
source scripts/common.sh
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1
ww_running && ./stop.sh
systemctl --user disable --now whitewidow-net.service 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/whitewidow-net.service" "$HOME/.local/share/applications/whitewidow-net.desktop"
[ -f /etc/sudoers.d/whitewidow-net ] && { say "Eliminando permiso sudo de nft"; sudo rm -f /etc/sudoers.d/whitewidow-net; }
rm -rf "$WW_DIR/.venv"
if [ "$PURGE" -eq 1 ]; then rm -rf "$WW_HOME" "$HOME/.config/whitewidow-net"; say "Datos y configuración eliminados."
else say "Datos conservados en $WW_HOME (usa --purge para borrarlos)."; fi
say "Desinstalado. Puedes borrar esta carpeta."
