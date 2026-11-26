# WhiteWidow Net

Plataforma de monitoreo, descubrimiento y administración de **redes autorizadas**: inventario de dispositivos, telemetría del equipo, detección de comportamientos sospechosos, perfiles de red que se reconocen solos y control de acceso mediante adaptadores. Dashboard web, sin depender de la terminal.

> Úsala solo en redes que administras o donde tienes autorización. El escaneo activo no se habilita hasta que declaras autorización para esa red.

## Instalación (Linux Mint / Ubuntu / Debian)
```bash
git clone https://github.com/ravesnoopy/WhiteWidow-net.git
cd WhiteWidow-net
./install.sh
```
El instalador usa el Python que ya trae Mint, crea un entorno aislado, instala dependencias, crea el acceso directo, inicia el servicio y abre el dashboard. No se ejecuta como root, no necesita sudo para funcionar (solo si falta `python3-venv`) y **no toca tu router**.

**Escucha pasiva (recomendado):** el instalador te pregunta si quieres habilitarla; pide `sudo` una sola vez para dar a una copia del Python el permiso de leer paquetes (`cap_net_raw`). Luego, en el dashboard, abre **Escucha pasiva**. Más tarde: `./scripts/enable-sniffer.sh` (o `--disable`).

Después: `./start.sh` · `./stop.sh` · `./start.sh --token` (solo si activas auth/LAN) · `./update.sh` · `./uninstall.sh [--purge]`.
Alternativa: paquete `.deb` (se construye con `deployment/build_deb.sh`; si hay un release publicado también está en GitHub Releases) → `sudo apt install ./whitewidow-net_1.2.0_all.deb` y luego `whitewidow-net serve`.

## Cómo se usa en una red
1. Conéctate a la red y arranca (`./start.sh`). El dashboard abre directo, sin contraseña.
2. WhiteWidow detecta interfaz, IP, gateway, subred, DNS y SSID y crea (o recupera) el perfil de esa red. En **modo pasivo** solo ve los dispositivos que ya hablaron con este equipo (tabla ARP, anuncios mDNS/DHCP/SSDP) y la telemetría local.
3. Si tienes autorización: **Perfiles de red → Autorizar**. Desde ahí hace un sondeo ARP + mDNS + SSDP (lista TODOS los dispositivos, WiFi y cable, y obtiene sus nombres), descubrimiento activo periódico (cada 5 min por defecto) y escaneo de puertos comunes, durante horas o días mientras esté encendido.
4. Cada 6 h y al detenerse genera un informe HTML en `~/.local/share/whitewidow-net/reports/`. También hay CSV, JSON de evidencia y el registro de auditoría.

Requisito para dejarlo trabajando durante días: que el equipo no se suspenda y siga conectado a esa red.

## Qué hace y qué no (resumen honesto)
| Capacidad | Estado v1.2.0 |
|---|---|
| Detección de red, perfiles, descubrimiento, inventario, fabricante | Implementado y probado |
| Conexiones y procesos **de este equipo**, tráfico de la interfaz | Implementado y probado |
| Alertas: dispositivo nuevo, gateway, puertos riesgosos, beaconing, picos, dominios, escaneo entrante | Implementado (reglas probadas con datos sintéticos) |
| Identificar dispositivos (nombre, MAC, fabricante, servicios, SO estimado) escuchando ARP/DHCP/mDNS/SSDP/NetBIOS, **con cualquier modem** | Implementado y probado (paquetes sintéticos y captura real) |
| Detectar escaneos hacia este equipo, intentos fallidos, barridos ARP, suplantación del gateway, DHCP duplicado | Implementado y probado (paquetes sintéticos) |
| Ver conexiones/dominios de **otros** dispositivos de la red | **Requiere** estar en el camino del tráfico (gateway/SPAN) + TShark/Zeek/ntopng, o AdGuard Home como DNS. TShark y AdGuard integrados; Zeek/ntopng/Arkime no |
| Bloquear/suspender dispositivos | nftables (solo si este equipo es el gateway). Routers comerciales sin API: **no soportado** |
| Bloquear dominios | AdGuard Home (los dispositivos deben usarlo como DNS) |
| Límite de ancho de banda, horarios, OPNsense/pfSense | **No implementado** |
| Windows / macOS | No implementado |

Detalle completo en [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Informe de pruebas en [docs/VALIDATION.md](docs/VALIDATION.md).

## Documentación
[Arquitectura](docs/ARCHITECTURE.md) · [Instalación](docs/INSTALL.md) · [Uso](docs/USAGE.md) · [Limitaciones](docs/LIMITATIONS.md) · [Publicar en GitHub](docs/GITHUB.md) · [Seguridad](SECURITY.md)

Licencia MIT.
