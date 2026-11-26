#!/usr/bin/env bash
# Construye dist/whitewidow-net_<versión>_all.deb  (requiere dpkg-deb)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
VER="$(python3 -c 'import whitewidow_net;print(whitewidow_net.__version__)')"
ROOT="$(mktemp -d)"; PKG="$ROOT/whitewidow-net"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/whitewidow-net" "$PKG/usr/bin" "$PKG/usr/share/applications"
cp -r whitewidow_net dashboard requirements.txt LICENSE README.md "$PKG/opt/whitewidow-net/"
find "$PKG" -name __pycache__ -prune -exec rm -rf {} +
cat > "$PKG/DEBIAN/control" <<CTRL
Package: whitewidow-net
Version: $VER
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-venv, libcap2-bin
Recommends: iputils-ping, tshark
Maintainer: WhiteWidow Net <noreply@example.invalid>
Description: Monitoreo, descubrimiento y administración de redes autorizadas
 Plataforma con dashboard web, inventario de dispositivos, telemetría y detección.
CTRL
cat > "$PKG/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
python3 -m venv /opt/whitewidow-net/.venv
/opt/whitewidow-net/.venv/bin/pip install --quiet -r /opt/whitewidow-net/requirements.txt
# Permiso de escucha pasiva sobre una copia del Python (no se toca el del sistema)
cp -f "$(readlink -f /opt/whitewidow-net/.venv/bin/python3)" /opt/whitewidow-net/.venv/bin/python-ww
setcap cap_net_raw=eip /opt/whitewidow-net/.venv/bin/python-ww || rm -f /opt/whitewidow-net/.venv/bin/python-ww
POST
cat > "$PKG/DEBIAN/prerm" <<'PRE'
#!/bin/sh
rm -rf /opt/whitewidow-net/.venv
PRE
chmod 755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"
cat > "$PKG/usr/bin/whitewidow-net" <<'BIN'
#!/bin/sh
# Ejecuta como el usuario actual (nunca root). Ej.: whitewidow-net serve | whitewidow-net token
[ "$(id -u)" -ne 0 ] || { echo "No ejecutes WhiteWidow Net como root." >&2; exit 1; }
PYTHONPATH=/opt/whitewidow-net exec /opt/whitewidow-net/.venv/bin/python -m whitewidow_net "$@"
BIN
chmod 755 "$PKG/usr/bin/whitewidow-net"
cat > "$PKG/usr/share/applications/whitewidow-net.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=WhiteWidow Net
Exec=sh -c 'whitewidow-net serve & sleep 3; xdg-open http://127.0.0.1:8787'
Terminal=false
Categories=Network;Security;
DESK
mkdir -p dist && dpkg-deb --build --root-owner-group "$PKG" "dist/whitewidow-net_${VER}_all.deb" >/dev/null
echo "dist/whitewidow-net_${VER}_all.deb"
