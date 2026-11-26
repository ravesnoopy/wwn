"""Configuración y rutas. Los tokens se generan en el primer arranque y el archivo queda con permisos 0600."""
import copy
import json
import os
import secrets
from pathlib import Path

DEFAULTS = {
    "host": "127.0.0.1",          # seguro por defecto: solo este equipo
    "port": 8787,
    "scan_interval": 300,         # segundos entre escaneos activos
    "passive_interval": 60,       # segundos entre lecturas pasivas de la tabla ARP
    "telemetry_interval": 5,
    "retention_days": 30,
    "report_interval_hours": 6,
    "max_scan_hosts": 1024,       # tope de seguridad (/22)
    "port_scan": True,            # escaneo de puertos comunes en dispositivos descubiertos
    "sniffer_enabled": True,       # escucha pasiva (necesita ./scripts/enable-sniffer.sh una vez)
    "sniffer_promiscuous": False, # solo útil si la interfaz ve tráfico ajeno (puerto espejo / gateway)
    "probe_discovery": True,      # en redes AUTORIZADAS: sondeo ARP + mDNS + SSDP para listar todos los dispositivos y sus nombres
    "watch_services": ["youtube", "netflix", "adulto"],  # compatibilidad: servicios con alerta (ver service_actions)
    "service_actions": {"youtube": "alertar", "netflix": "alertar", "adulto": "alertar"},  # política por servicio: alertar | bloquear (sin entrada = permitir)
    "custom_services": [],        # reglas propias del Firewall: [{"key","label","pattern"}]
    "control_enabled": False,     # modo pasivo por defecto
    "control_dry_run": True,      # aunque se habilite el control, simula hasta desactivar esto
    "auth_enabled": False,        # solo local: sin login. Si escuchas en la LAN, el token se exige siempre
    "admin_token": "",
    "viewer_token": "",
    "integrations": {
        "adguard": {"enabled": False, "url": "", "username": "", "password": ""},
        "tshark": {"enabled": False, "interface": ""},
        "nftables": {"enabled": False},
    },
}
SECRET_KEYS = {"admin_token", "viewer_token", "password"}


def data_dir() -> Path:
    p = Path(os.environ.get("WW_HOME") or Path.home() / ".local/share/whitewidow-net")
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_path() -> Path:
    return Path(os.environ.get("WW_CONFIG") or Path.home() / ".config/whitewidow-net/config.json")


def _merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def save(cfg: dict) -> None:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def load() -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    p = config_path()
    if p.exists():
        try:
            _merge(cfg, json.loads(p.read_text()))
        except json.JSONDecodeError:
            raise SystemExit(f"Config inválida: {p}. Corrígela o bórrala para regenerarla.")
    changed = not p.exists()
    for k in ("admin_token", "viewer_token"):
        if not cfg[k]:
            cfg[k] = secrets.token_urlsafe(32)
            changed = True
    if changed:
        save(cfg)
    return cfg


def masked(cfg: dict) -> dict:
    out = copy.deepcopy(cfg)

    def walk(d):
        for k, v in d.items():
            if isinstance(v, dict):
                walk(v)
            elif k in SECRET_KEYS and v:
                d[k] = "********"
    walk(out)
    return out
