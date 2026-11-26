# Informe de validación — v1.1.0
Entorno: contenedor Ubuntu 24.04, Python 3.12, usuario no root. **No se probó en Linux Mint físico, con Wi-Fi real ni con modems ZTE/Hitron/Multicolor.**

| Verificación v1.1.0 | Resultado |
|---|---|
| 61 pruebas automáticas (`pytest`) | OK |
| Parsers ARP/DHCP/mDNS/SSDP/NetBIOS/DNS/TLS-SNI con paquetes construidos a mano, incluidos paquetes basura aleatorios y bucle de compresión DNS | OK |
| Detección: barrido ARP, escaneo de puertos con intentos fallidos, conflicto ARP del gateway, DHCP duplicado, tráfico ajeno visible; casos normales NO generan falsas alertas | OK (sintético) |
| Captura real con socket AF_PACKET (loopback, y interfaz eth0 enviando mDNS real) | OK |
| Proceso de escucha como usuario no root con `cap_net_raw` en `python-ww` (setcap) | OK |
| Sin permiso: estado "no_permission" con la solución visible en el dashboard (error real encontrado y corregido durante la validación) | OK |
| `enable-sniffer.sh`: verificación como usuario sin privilegios (evita falso "listo" al ejecutar como root) | OK |
| Dashboard: 16 secciones sin errores, login oculto (estilos calculados, jsdom) | OK. Sin navegador gráfico real |
| Parada limpia: sin procesos huérfanos tras `stop.sh` | OK |
| Migración de BD v1.0.x → v1.1.0 | OK |

**No verificado:** escaneos reales de terceros (solo paquetes sintéticos, la lógica no se midió contra nmap/Fing reales), consumo de CPU con mucho tráfico, mDNS/DHCP/SSDP de dispositivos reales (los formatos siguen los estándares pero cada fabricante varía), `.deb` con permisos en un Mint real, ejecución de días.

---
# Validación anterior — v1.0.1
**v1.0.1:** 39 pruebas OK (nuevas: sin login, bloqueo de Origin/Host ajeno, token forzado en LAN, grabación JSON, horas pico). El fallo del login (CSS `display` vs `hidden`) se reprodujo con estilos calculados (jsdom) y se verificó corregido. Sigue sin probarse en un navegador gráfico real; la validación original v1.0.0 se conserva abajo.

# Validación original — v1.0.0
Entorno de prueba: contenedor Ubuntu 24.04, Python 3.12.3, usuario no root, sin `ip`/`ping` (prueba del modo de respaldo). **No se probó en Linux Mint físico ni con routers reales.**

## Resultados
| # | Verificación | Resultado |
|---|---|---|
| 1 | Instalación desde cero como usuario normal (`./install.sh`, venv + pip) | OK |
| 2 | Pruebas automatizadas (`pytest`): 33 pruebas unitarias/integración | 33 OK |
| 3 | API: autenticación, roles admin/viewer, cabeceras de seguridad, validación de entradas | OK (probado) |
| 4 | Dashboard: carga y renderizado de las 15 secciones contra el servidor real (jsdom, sin errores JS) | OK. **No** probado en navegador gráfico real ni en móvil |
| 5 | Persistencia SQLite (reinicio del servicio conserva dispositivos y perfiles) | OK |
| 6 | Detección de red real (interfaz, IP, gateway, MAC del gateway, subred, DNS) | OK en el contenedor |
| 7 | Descubrimiento activo real de una /24 y descubrimiento en loopback | OK (2 hosts) |
| 8 | Reconocimiento de red: misma red con IP/SSID distinto, misma subred con otro gateway, sin MAC de gateway, cambio de MAC de gateway (alerta) | OK |
| 9 | Escaneo rechazado en rangos públicos y > 1024 hosts | OK |
| 10 | Modo pasivo hasta autorizar; autorización requiere confirmación y se audita | OK |
| 11 | Control: deshabilitado por defecto, exige confirmación, valida objetivo, rechaza acciones sin adaptador, dry-run no ejecuta | OK. Sin cambios en ningún router |
| 12 | Detecciones con datos sintéticos: beaconing (+deduplicación), dominios sospechosos, gateway, dispositivo nuevo | OK |
| 13 | Inicio/parada con `start.sh`/`stop.sh`, informe final generado al detener | OK |
| 14 | Paquete `.deb`: construcción, instalación, ejecución como usuario, desinstalación | OK |
| 15 | Permisos: `config.json` 0600, scripts ejecutables, no se ejecuta como root | OK |
| 16 | Sin credenciales, bases de datos ni configuraciones en el ZIP | OK (escaneo) |
| 17 | ZIP extraíble; desde el contenido extraído: 33 pruebas OK, `install.sh` → `start.sh` → `stop.sh` → `uninstall.sh --purge` OK | OK |

## No verificado (requiere hardware o entorno real)
- Linux Mint físico, Wi-Fi/SSID real, systemd de usuario (`--service`), acceso directo de escritorio, `xdg-open`.
- nftables real (`nft` no disponible en el entorno): solo se validó la generación y validación de comandos.
- AdGuard Home real: solo validación de reglas de dominio; las llamadas REST **no se probaron contra un servidor real**.
- TShark: el adaptador no se ejecutó (no instalado).
- Detección de escaneo entrante, picos de tráfico y procesos sospechosos: lógica implementada; solo pruebas parciales.
- Ejecución continua durante días (estabilidad/memoria).
- Mint 21/22, Python 3.9–3.11 (CI de GitHub los cubrirá al publicar).
- Windows/macOS: no implementados.
