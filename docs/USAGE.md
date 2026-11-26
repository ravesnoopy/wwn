# Uso
1. `./start.sh`: el dashboard abre directo, sin contraseña (el token solo se pide con `--lan` o `"auth_enabled": true`).
   **Grabar:** en Resumen, "● Grabar sesión" → "■ Detener y guardar JSON" (`~/.local/share/whitewidow-net/recordings/`).
2. **Escucha pasiva**: estado, contadores y eventos (escaneos, intentos fallidos, barridos ARP, conflictos). Si dice "Sin permiso", ejecuta una vez `./scripts/enable-sniffer.sh`.
2b. **Resumen**: red actual, dispositivos activos, conexiones, alertas, tráfico.
3. **Perfiles de red**: nombra la red (Home/Office/Second Home/Custom) y pulsa *Autorizar* si tienes permiso para escanear activamente.
4. **Dispositivos**: clic en uno para abrir el **Centro de investigación** (línea de tiempo, propietario, etiqueta, exportar evidencia JSON).
5. **Amenazas**: cambia el estado (open → investigating → resolved/false_positive); clic para ver la evidencia.
6. **Control de red**: muestra qué acciones permite *tu* infraestructura. Todo requiere habilitar el control en Ajustes, confirmar cada acción y queda en Auditoría. Arranca en simulación.
7. **Informes**: Ajustes → Informe HTML / CSV.
CLI: `python -m whitewidow_net status | scan [--authorize] | report | token`.
Para ver el dashboard desde el móvil: `./start.sh --lan` y abre `http://IP-del-equipo:8787` (solo en red de confianza; nunca expongas a Internet).
