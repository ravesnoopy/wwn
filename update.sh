#!/usr/bin/env bash
# Actualiza desde GitHub (git pull) y reinstala dependencias. Conserva datos y configuración.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
source scripts/common.sh
[ -d .git ] || die "No es un clon de git. Descarga la nueva versión y vuelve a ejecutar ./install.sh"
was=0; ww_running && was=1 && ./stop.sh
git pull --ff-only
"$WW_DIR/.venv/bin/pip" install --quiet -r requirements.txt
say "Actualizado a $("$WW_PY" -c 'import whitewidow_net;print(whitewidow_net.__version__)')"
[ "$was" -eq 0 ] || ./start.sh --no-browser
