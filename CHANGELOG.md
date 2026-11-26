# Changelog
Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) · Versionado: [SemVer](https://semver.org/lang/es/)

## [2.0.0] - 2026-11-25
### Interfaz
- Encabezado fijo: RED (gateway) · ENDPOINT (nombre / IP, conectado o desconectado) · modo claro/oscuro (☀/☾, claro = hueso/blanco, oscuro = gris y beige) · Salir.
- **Actualización cada 5 s sin parpadeo ni salto de scroll** (los desplegables abiertos se conservan) y botón "Actualizar" en las listas.
- **Resumen** rehecho: tarjetas grandes (Dispositivos, Firewall en amarillo con entradas a servicios vigilados, Alertas en rojo sin revisar, Subida y bajada juntas), conexiones y desconexiones, **Dominios y apps sin repeticiones** (clic para ver por dispositivo las últimas 10 visitas; regla de 30 min), datos usados compacto, tráfico con leyenda de círculos y periodo abajo, últimas actividades por color, Descubrimiento al final, Grabar en rojo.
- **Dispositivos:** foco verde parpadeante / rojo fijo, nombre siempre legible, "Detectado como" ampliado (nunca "desconocido"), categoría automática, tabla compacta y filtros en una fila.
- **Firewall** (antes Actividad): Permitir / Alertar / Bloquear por servicio en cuadrícula de 5, más servicios (resto en "Otros") y reglas propias por nombre + dominio/link (incluye subdominios).
- Renombres y orden: Aplicaciones → Servicios y herramientas (por dispositivo, un desplegable a la vez); Descubrimiento dentro de Resumen; Auditoría dentro de Ajustes ("Auditoría de dispositivo"); Perfiles de red al final.
- Escucha pasiva en dos filas de 5 (sin SSDP/UPnP), todos los dispositivos detectados, criticidad por color y "Guardar lista actual" (CSV) en las tablas.
- Amenazas medias/altas parpadean hasta cerrarse; Control de acceso en español, solo dispositivos finales, confirmación escribiendo "bloquear" / "desbloquear" / "limitar"; Integraciones con descripción; Investigación con criticidad y actualización automática; Procesos con criticidad y proceso padre.
### API
- Nuevos: `/api/dashboard`, `/api/groups`, `/api/feed`, `/api/firewall` (+ reglas propias), `/api/device-services`, `/api/analytics/device-peaks`. Dispositivos con `display_name`, `detected_as`, `is_endpoint`. Conexiones con `level` y dispositivo.
- Tabla `domain_visits` (visitas por dispositivo, 30 min) y política por servicio `service_actions`.
### Límite que sigue
- La actividad de OTROS dispositivos (dominios, apps, MB/GB) requiere una fuente de tráfico (DNS del router hacia AdGuard Home, gateway o puerto espejo). Sin ella WhiteWidow lista todos los dispositivos, pero solo ve la actividad de este equipo.

## [1.2.0] - 2026-11-25
### Corregido
- **El gráfico de tráfico no mostraba nada**: se dibujaba antes de insertarse en la página (medía 0 px). Ahora se dibuja ya insertado.
- README/INSTALL/GITHUB: la URL de clonado era un marcador (`TU_USUARIO/WHITEWIDOWNET`); ahora apunta a `ravesnoopy/WhiteWidow-net`.
### Añadido
- **Categoría por dispositivo** (Teléfono, Tablet, TV, Computadora, Router, Impresora, IoT, Cámara) con motivo y confianza; se puede corregir a mano y queda guardada (`user_type`). Filtros y conteo por categoría.
- **Sondeo de descubrimiento** (solo en redes autorizadas, ajuste `probe_discovery`): solicitudes ARP a la subred (2 pasadas), consulta mDNS y SSDP estándar. Lista dispositivos WiFi y por cable y consigue nombres y servicios. El botón "Escanear ahora" también lo lanza.
- **Servicios reconocidos por dominio** (YouTube, Netflix, Disney+, Prime Video, Max, Twitch, TikTok, Instagram, Facebook, WhatsApp, Discord, Spotify, Zoom, Steam, Roblox, Epic y sitios para adultos) y **alerta** `WATCHED_SERVICE` para los vigilados (por defecto YouTube, Netflix y adultos; se cambia en la vista Actividad).
- Vista **Actividad**: qué servicio se vio, desde qué dispositivo y cuántas veces.
- **Conexiones filtradas**: se oculta el ruido (escuchas locales, LAN/multicast, DNS, NTP, DHCP, mDNS, SSDP, NetBIOS) y cada destino se traduce a servicio/dominio con las respuestas DNS vistas. Casilla "Mostrar todo".
- **Datos usados en MB/GB**: última hora, hoy, 24 h y 7 días, por hora y por día (`/api/traffic/summary`).
### Nota
- Con escucha pasiva en una red normal solo se ve la actividad de ESTA computadora; los demás dispositivos no envían su tráfico a este equipo (ver docs/LIMITATIONS.md).

## [1.1.0] - 2026-11-25
### Añadido
- **Escucha pasiva** (funciona con cualquier modem/router; no envía paquetes): identifica dispositivos por ARP, DHCP (nombre, clase de fabricante, SO estimado), mDNS/Bonjour y SSDP/UPnP (servicios y tipo), NetBIOS.
- Detección de **escaneos hacia este equipo**: barridos ARP, escaneo de puertos (SYN), pings, e **intentos de conexión fallidos** (puertos cerrados).
- Alertas: conflicto ARP / posible suplantación del gateway, varios servidores DHCP, barrido ARP, escaneo de puertos entrante.
- Si la interfaz ve tráfico ajeno (gateway/puerto espejo): consultas DNS y SNI de TLS atribuidas a cada dispositivo; resets TCP.
- Vista "Escucha pasiva" en el dashboard; eventos de red incluidos en la grabación JSON.
- `scripts/enable-sniffer.sh`: concede **solo** cap_net_raw a una copia del Python del entorno (python-ww); el servidor web sigue sin privilegios. El instalador lo ofrece; el .deb lo hace en postinst.
- Migración automática de bases de datos v1.0.x.
- Dispositivos no vistos durante mucho tiempo pasan a "fuera".

## [1.0.1] - 2026-11-25
### Corregido
- **El dashboard no abría tras ingresar el token**: `display:grid` del login anulaba el atributo `hidden` y la pantalla de login tapaba la app. Ahora `[hidden]` siempre oculta.
### Cambiado
- **Sin login por defecto** en modo local (`auth_enabled: false`). Se protege con: escucha solo en 127.0.0.1, rechazo de Host ajeno (DNS rebinding) y de peticiones de otros sitios web (Origin). Si se usa `--lan`/otro host, el token se exige siempre.
### Añadido
- Grabación de sesiones: botón "Grabar sesión" → al detener se guarda un JSON en `~/.local/share/whitewidow-net/recordings/` (también se guarda al apagar el servicio).
- Horas pico de uso (promedio por hora del tráfico de este equipo).

## [1.0.0] - 2026-11-23
### Añadido
- Detección automática de red (interfaz, IP, gateway, MAC del gateway, subred, DNS, SSID) y perfiles reconocidos por múltiples señales.
- Descubrimiento pasivo (tabla ARP) y activo (ping/TCP + puertos comunes) restringido a rangos privados y redes autorizadas.
- Inventario de dispositivos con fabricante (OUI), tipo/SO estimados, historial de actividad.
- Telemetría del endpoint: conexiones, procesos con actividad de red, tráfico de la interfaz.
- Detecciones: dispositivo nuevo, cambio de MAC del gateway, puertos riesgosos, beaconing, picos de tráfico, dominios sospechosos, escaneo entrante, procesos en rutas temporales.
- Control de acceso: adaptadores nftables y AdGuard Home, con dry-run, confirmación y auditoría.
- Dashboard web (15 secciones), informes HTML/CSV/JSON, API autenticada por token.
- Scripts de instalación, inicio, parada, actualización y desinstalación; unidad systemd de usuario; paquete DEB.
### Limitaciones conocidas
Ver `docs/LIMITATIONS.md`.
