# Política de seguridad
## Uso autorizado
WhiteWidow Net es para redes que administras o donde tienes **autorización escrita** para monitorear. El escaneo activo está deshabilitado hasta que el operador declara autorización por red (queda en la auditoría).

## Diseño seguro por defecto
- Se ejecuta como usuario normal, nunca como root. El descubrimiento no requiere privilegios.
- El dashboard escucha solo en `127.0.0.1`. `--lan` es opt-in explícito. **No lo expongas a Internet.**
- Sin login en modo local (solo 127.0.0.1): se rechazan Host ajeno y peticiones con Origin de otro sitio. Si el servicio escucha fuera de localhost o pones `"auth_enabled": true` en `config.json`, se exige token (admin / solo lectura), generado aleatoriamente, con `config.json` en 0600. Cualquier usuario o programa de este mismo equipo puede usar la API local.
- Modo pasivo por defecto; el control de red requiere habilitarlo, confirmación en cada acción y queda auditado. Además arranca en simulación (`control_dry_run`).
- Escaneo restringido a rangos privados y a un máximo de 1024 hosts.
- No se guardan contenidos de tráfico, solo metadatos. Solo se registran procesos con actividad de red.
- Entradas validadas (pydantic, `ipaddress`, expresiones de dominio); subprocesos sin shell; informes con escape HTML y neutralización de inyección CSV.

## Escucha pasiva y permisos
La captura de paquetes necesita `cap_net_raw`. Se concede solo a una **copia** del intérprete (`.venv/bin/python-ww`) con `setcap`, no al Python del sistema, y solo la usa el proceso `whitewidow_net.sniffer`, que no envía paquetes ni abre puertos. El servidor web y el dashboard corren sin ese permiso. Quien pueda modificar los archivos de la carpeta de instalación podría ejecutar código con cap_net_raw: mantén la carpeta con tu usuario y permisos normales. Retirar: `./scripts/enable-sniffer.sh --disable`.

## Reportar una vulnerabilidad
Abre un *security advisory* privado en GitHub (pestaña Security → Report a vulnerability). No publiques detalles hasta que haya corrección.
