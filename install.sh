#!/usr/bin/env bash
# WhiteWidow Net - instalador para Linux Mint / Ubuntu / Debian. No requiere root salvo para instalar paquetes del sistema que falten.
# Uso: ./install.sh [--no-start] [--no-desktop] [--service] [--with-control] [--sniffer | --no-sniffer]
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
source scripts/common.sh
START=1; DESKTOP=1; SERVICE=0; CONTROL=0; SNIFFER=ask
for a in "$@"; do case "$a" in
  --no-start) START=0;; --no-desktop) DESKTOP=0;; --service) SERVICE=1;; --with-control) CONTROL=1;; --sniffer) SNIFFER=yes;; --no-sniffer) SNIFFER=no;;
  -h|--help) sed -n '2,3p' "$0"; exit 0;; *) die "Opción desconocida: $a";; esac; done
[ "$(id -u)" -ne 0 ] || die "No ejecutes el instalador como root. Se pedirá sudo solo si hace falta."
exec > >(tee -a "$WW_HOME/logs/install.log") 2>&1
say "Instalando WhiteWidow Net en $WW_DIR (log: $WW_HOME/logs/install.log)"

need_apt=()
command -v python3 >/dev/null || need_apt+=(python3)
python3 -c 'import venv, ensurepip' 2>/dev/null || need_apt+=(python3-venv)
command -v ping >/dev/null || warn "ping no encontrado: se usará descubrimiento TCP/ARP (recomendado: sudo apt install iputils-ping)"
if [ "${#need_apt[@]}" -gt 0 ]; then
  say "Faltan paquetes del sistema: ${need_apt[*]}  (se pedirá tu contraseña de sudo)"
  command -v apt-get >/dev/null || die "Instala manualmente: ${need_apt[*]}"
  sudo apt-get update -qq && sudo apt-get install -y "${need_apt[@]}"
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' || die "Se requiere Python 3.9 o superior."

say "Creando entorno aislado e instalando dependencias..."
[ -x "$WW_PY" ] || python3 -m venv "$WW_DIR/.venv"
"$WW_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$WW_DIR/.venv/bin/pip" install --quiet -r "$WW_DIR/requirements.txt"
(cd "$WW_DIR" && "$WW_PY" -m whitewidow_net init)
chmod +x "$WW_DIR"/*.sh "$WW_DIR"/scripts/*.sh

if [ "$DESKTOP" -eq 1 ]; then
  mkdir -p "$HOME/.local/share/applications"
  cat > "$HOME/.local/share/applications/whitewidow-net.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=WhiteWidow Net
Comment=Monitoreo y descubrimiento de redes autorizadas
Exec=$WW_DIR/start.sh
Terminal=false
Categories=Network;Security;
DESK
  say "Acceso directo creado en el menú de aplicaciones."
fi
if [ "$SERVICE" -eq 1 ]; then
  mkdir -p "$HOME/.config/systemd/user"
  sed "s|@WW_DIR@|$WW_DIR|g" deployment/whitewidow-net.service > "$HOME/.config/systemd/user/whitewidow-net.service"
  systemctl --user daemon-reload && systemctl --user enable --now whitewidow-net.service && say "Servicio de usuario habilitado (reinicio automático ante fallos)."
fi
if [ "$CONTROL" -eq 1 ]; then
  NFT="$(command -v nft || true)"; [ -n "$NFT" ] || die "nft no está instalado: sudo apt install nftables"
  say "Se habilitará permiso sudo SIN contraseña solo para: $NFT (necesario para el control de red). Esto equivale a control total del firewall."
  read -r -p "¿Continuar? [s/N] " r; [ "$r" = "s" ] || die "Cancelado."
  echo "$USER ALL=(root) NOPASSWD: $NFT" | sudo tee /etc/sudoers.d/whitewidow-net >/dev/null
  sudo chmod 440 /etc/sudoers.d/whitewidow-net && sudo visudo -cf /etc/sudoers.d/whitewidow-net >/dev/null
fi
if [ "$SNIFFER" = "ask" ] && [ -t 0 ]; then
  say "La escucha pasiva (detectar dispositivos y escaneos en la red) necesita un permiso de captura, que se concede una sola vez con sudo."
  read -r -p "¿Habilitarla ahora? [S/n] " r; case "${r:-S}" in [sS]*|[yY]*) SNIFFER=yes;; *) SNIFFER=no;; esac
fi
if [ "$SNIFFER" = "yes" ]; then "$WW_DIR/scripts/enable-sniffer.sh" || warn "No se pudo habilitar la escucha pasiva. Puedes reintentar con ./scripts/enable-sniffer.sh"
elif [ "$SNIFFER" != "yes" ]; then say "Escucha pasiva sin habilitar. Actívala cuando quieras con ./scripts/enable-sniffer.sh"; fi
say "Instalación completa. No se modificó ninguna configuración de tu router."
if [ "$START" -eq 1 ]; then exec "$WW_DIR/start.sh"; else say "Inicia con: ./start.sh"; fi
