# Instalación
**Requisitos:** Linux Mint 21/22 (o Ubuntu/Debian), Python ≥ 3.9 (viene instalado), 1 GB RAM, ~200 MB de disco, conexión a Internet solo durante la instalación (descarga de `fastapi`, `uvicorn`, `psutil`).
**Permisos:** usuario normal. `sudo` solo si faltan `python3-venv` o si eliges `--with-control`.

```bash
git clone https://github.com/ravesnoopy/WhiteWidow-net.git && cd WhiteWidow-net && ./install.sh
```
Opciones: `--no-start`, `--no-desktop`, `--service` (servicio systemd de usuario con reinicio automático), `--with-control` (permiso sudo sin contraseña solo para `nft`; equivale a control total del firewall, úsalo solo si este equipo será el gateway).

El dashboard no pide contraseña en modo local. Registros: `~/.local/share/whitewidow-net/logs/`. Configuración: `~/.config/whitewidow-net/config.json` (0600).
Servicio permanente al iniciar sesión: `./install.sh --service` y `loginctl enable-linger $USER` para que siga sin sesión abierta.
Desinstalar: `./uninstall.sh` (conserva datos) o `./uninstall.sh --purge`.
Escucha pasiva: `./scripts/enable-sniffer.sh` (sudo una vez; instala `libcap2-bin` si falta).
Opcional: `sudo apt install tshark` y habilitar en Ajustes para registrar consultas DNS (requiere permisos de captura).
