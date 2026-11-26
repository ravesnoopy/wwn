"""CLI: python -m whitewidow_net [serve|token|status|scan|authorize|report|init]"""
import argparse
import logging
import sys

from . import __version__, config


def main(argv=None):
    ap = argparse.ArgumentParser(prog="whitewidow-net", description=f"WhiteWidow Net v{__version__}")
    sub = ap.add_subparsers(dest="cmd")
    sv = sub.add_parser("serve", help="inicia el servicio y el dashboard (por defecto)")
    sv.add_argument("--host")
    sv.add_argument("--port", type=int)
    sub.add_parser("token", help="muestra los tokens de acceso al dashboard")
    sub.add_parser("init", help="crea la configuración si no existe")
    sub.add_parser("status", help="muestra la red detectada")
    sc = sub.add_parser("scan", help="detecta la red y ejecuta un escaneo ahora")
    sc.add_argument("--authorize", action="store_true", help="declaras autorización sobre la red actual (habilita escaneo activo)")
    sub.add_parser("report", help="genera un informe HTML")
    a = ap.parse_args(argv)
    cfg = config.load()
    cmd = a.cmd or "serve"
    if cmd == "init":
        print(f"Configuración: {config.config_path()}")
    elif cmd == "token":
        print(f"Administrador: {cfg['admin_token']}\nSolo lectura:  {cfg['viewer_token']}")
    elif cmd == "status":
        from . import netinfo
        for k, v in netinfo.detect().items():
            print(f"{k}: {v}")
    elif cmd in ("scan", "report"):
        from .db import DB
        from .monitor import Monitor
        db = DB(config.data_dir() / "whitewidow.db")
        m = Monitor(db, cfg)
        if cmd == "report":
            print(m.write_report())
            return 0
        m.refresh_network()
        if not m.network:
            print("Sin red conectada.")
            return 1
        if a.authorize:
            db.execute("UPDATE networks SET authorized=1 WHERE id=?", (m.network["id"],))
            db.audit("cli", "network_authorized", m.network["id"], "autorizada desde CLI")
        print(m.run_scan())
    else:
        import uvicorn
        from .api import create_app
        if getattr(a, "host", None):
            cfg["host"] = a.host
        if getattr(a, "port", None):
            cfg["port"] = a.port
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        if cfg["host"] not in ("127.0.0.1", "localhost", "::1"):
            logging.warning("El dashboard escucha en %s (no solo local). Protégelo con firewall; NO lo expongas a Internet.", cfg["host"])
        uvicorn.run(create_app(cfg), host=cfg["host"], port=cfg["port"], log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
