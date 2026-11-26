# Funciones compartidas por los scripts. Se usa con `source`.
WW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WW_HOME="${WW_HOME:-$HOME/.local/share/whitewidow-net}"
WW_PID="$WW_HOME/whitewidow.pid"
WW_LOG="$WW_HOME/logs/whitewidow.log"
WW_PY="$WW_DIR/.venv/bin/python"
mkdir -p "$WW_HOME/logs"
say()  { printf '\033[1;36m[WhiteWidow]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[aviso]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
ww_running() { [ -f "$WW_PID" ] && kill -0 "$(cat "$WW_PID")" 2>/dev/null; }
ww_port() { "$WW_PY" - <<'PY'
from whitewidow_net import config
print(config.load()["port"])
PY
}
