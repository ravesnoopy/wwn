"""API REST (FastAPI). Autenticación por token (admin/viewer), cabeceras seguras y validación de entradas."""
import hmac
import json
import logging
import re
import time
from datetime import datetime
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, config, fingerprint, reports, services, usage
from .control import Control, ControlError
from .db import DB
from .monitor import Monitor
from .telemetry import KNOWN_APPS, PORT_SERVICES

DASH = Path(__file__).resolve().parent.parent / "dashboard"


class NetworkPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    kind: Optional[Literal["Home", "Office", "Second Home", "Custom"]] = None


class AuthorizeBody(BaseModel):
    confirm: bool = False


class DevicePatch(BaseModel):
    owner: Optional[str] = Field(None, max_length=80)
    label: Optional[str] = Field(None, max_length=80)
    trusted: Optional[bool] = None
    user_type: Optional[str] = Field(None, max_length=30)  # categoría elegida por la persona; "" la quita


class AlertPatch(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]


class ControlBody(BaseModel):
    action: str = Field(max_length=30)
    target: str = Field(max_length=253)
    confirm: bool = False
    minutes: Optional[int] = Field(None, ge=1, le=1440)


class DomainBody(BaseModel):
    domain: str = Field(max_length=253)
    device_id: int = 0


class AdguardSet(BaseModel):
    enabled: Optional[bool] = None
    url: Optional[str] = Field(None, max_length=200)
    username: Optional[str] = Field(None, max_length=80)
    password: Optional[str] = Field(None, max_length=200)


class SettingsPatch(BaseModel):
    control_enabled: Optional[bool] = None
    control_dry_run: Optional[bool] = None
    scan_interval: Optional[int] = Field(None, ge=30, le=86400)
    port_scan: Optional[bool] = None
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    adguard: Optional[AdguardSet] = None
    sniffer_enabled: Optional[bool] = None
    sniffer_promiscuous: Optional[bool] = None
    probe_discovery: Optional[bool] = None
    watch_services: Optional[List[str]] = Field(None, max_length=40)
    tshark_enabled: Optional[bool] = None
    nftables_enabled: Optional[bool] = None


RISKY_PORTS = {23, 2323, 135, 139, 445, 3389, 4444, 5900, 6667, 31337}


def create_app(cfg: Optional[dict] = None, start_monitor: bool = True) -> FastAPI:
    cfg = cfg or config.load()
    db = DB(config.data_dir() / "whitewidow.db")
    mon = Monitor(db, cfg)

    @asynccontextmanager
    async def lifespan(app):
        if start_monitor:
            mon.start()
        yield
        if start_monitor:
            await mon.stop()
        db.close()

    app = FastAPI(title="WhiteWidow Net", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.db, app.state.mon, app.state.cfg = db, mon, cfg
    hosts = ["localhost", "127.0.0.1", "[::1]", "testserver"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"] if cfg["host"] not in ("127.0.0.1", "localhost") else hosts)

    @app.middleware("http")
    async def headers(request, call_next):
        # Sin login: bloquea peticiones de otros sitios web (CSRF) que intenten usar la API local.
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD", "OPTIONS") and origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            return Response("Origen no permitido", status_code=403)
        resp = await call_next(request)
        resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                             "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
                             "Cache-Control": "no-store" if request.url.path.startswith("/api") else "no-cache"})
        return resp

    loopback = cfg["host"] in ("127.0.0.1", "localhost", "::1")
    auth_required = cfg["auth_enabled"] or not loopback  # fuera de localhost siempre se exige token

    def auth(authorization: str = Header(default="")) -> str:
        if not auth_required:
            return "admin"
        tok = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        if tok and hmac.compare_digest(tok, cfg["admin_token"]):
            return "admin"
        if tok and hmac.compare_digest(tok, cfg["viewer_token"]):
            return "viewer"
        raise HTTPException(401, "Token inválido o ausente")

    def admin(role: str = Depends(auth)) -> str:
        if role != "admin":
            raise HTTPException(403, "Se requiere rol administrador")
        return role

    def like(q):
        return f"%{q}%" if q else "%"

    # ---------- público ----------
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__, "auth_required": auth_required}

    # ---------- lectura ----------
    @app.get("/api/overview")
    def overview(role=Depends(auth)):
        net = mon.network
        nid = net["id"] if net else -1
        one = lambda q, p=(): db.one(q, p)["c"]
        tr = db.one("SELECT * FROM traffic ORDER BY ts DESC LIMIT 1")
        return {"version": __version__, "connected": mon.sig.get("connected", False), "signal": {k: v for k, v in mon.sig.items()},
                "network": net, "scanning": mon.scanning, "control_enabled": cfg["control_enabled"], "dry_run": cfg["control_dry_run"],
                "devices_total": one("SELECT COUNT(*) c FROM devices WHERE network_id=?", (nid,)),
                "devices_online": one("SELECT COUNT(*) c FROM devices WHERE network_id=? AND online=1", (nid,)),
                "connections": one("SELECT COUNT(*) c FROM connections WHERE ts_last>strftime('%s','now')-3600"),
                "domains": one("SELECT COUNT(*) c FROM domains"),
                "apps": one("SELECT COUNT(DISTINCT process) c FROM connections WHERE process IS NOT NULL"),
                "alerts_open": one("SELECT COUNT(*) c FROM alerts WHERE status='open'"),
                "traffic": tr, "recent": db.query("SELECT a.ts,a.event,a.detail,d.ip FROM device_activity a JOIN devices d ON d.id=a.device_id ORDER BY a.ts DESC LIMIT 12")}

    @app.get("/api/networks")
    def networks(role=Depends(auth)):
        return db.query("SELECT n.*, (SELECT COUNT(*) FROM devices d WHERE d.network_id=n.id) devices, (SELECT COUNT(*) FROM scans s WHERE s.network_id=n.id) scans FROM networks n ORDER BY last_seen DESC")

    @app.patch("/api/networks/{nid}")
    def patch_network(nid: int, body: NetworkPatch, role=Depends(admin)):
        if not db.one("SELECT id FROM networks WHERE id=?", (nid,)):
            raise HTTPException(404)
        if body.name:
            db.execute("UPDATE networks SET name=? WHERE id=?", (body.name, nid))
        if body.kind:
            db.execute("UPDATE networks SET kind=? WHERE id=?", (body.kind, nid))
        db.audit(role, "network_updated", nid, body.model_dump_json(exclude_none=True))
        return {"ok": True}

    @app.post("/api/networks/{nid}/authorize")
    def authorize(nid: int, body: AuthorizeBody, role=Depends(admin)):
        if not body.confirm:
            raise HTTPException(400, "Debes confirmar que tienes autorización para escanear esta red.")
        if not db.one("SELECT id FROM networks WHERE id=?", (nid,)):
            raise HTTPException(404)
        db.execute("UPDATE networks SET authorized=1 WHERE id=?", (nid,))
        db.audit(role, "network_authorized", nid, "El operador declara autorización para escaneo activo")
        mon.last_scan = 0.0
        return {"ok": True}

    @app.post("/api/networks/{nid}/revoke")
    def revoke(nid: int, role=Depends(admin)):
        db.execute("UPDATE networks SET authorized=0 WHERE id=?", (nid,))
        db.audit(role, "network_authorization_revoked", nid)
        return {"ok": True}

    @app.post("/api/scan")
    async def scan_now(role=Depends(admin)):
        import asyncio
        if not mon.network:
            raise HTTPException(409, "Sin red conectada")
        r = await asyncio.to_thread(mon.run_scan)
        db.audit(role, "scan_manual", mon.network["name"], json.dumps(r))
        return r or {"mode": "busy"}

    def with_category(row):
        c = fingerprint.category(row)
        row["category"], row["category_basis"], row["category_confidence"] = c["category"], c["basis"], c["confidence"]
        row["display_name"] = fingerprint.display_name(row, c["category"])
        row["detected_as"] = fingerprint.detected_as(row, c["category"])
        row["is_endpoint"] = c["category"] in fingerprint.ENDPOINT_CATEGORIES and not row.get("is_gateway") and not row.get("is_self")
        return row

    def device_map():
        nid = mon.network["id"] if mon.network else -1
        return {d["id"]: with_category(d) for d in db.query("SELECT * FROM devices WHERE network_id=?", (nid,))}

    def dname(devs, did):
        d = devs.get(did)
        return (d["display_name"], d["ip"]) if d else ("Dispositivo no identificado", "")

    @app.get("/api/devices")
    def devices(q: str = "", network_id: Optional[int] = None, category: str = "", limit: int = Query(500, le=2000), role=Depends(auth)):
        nid = network_id if network_id is not None else (mon.network["id"] if mon.network else -1)
        rows = db.query("SELECT * FROM devices WHERE network_id=? AND (ip LIKE ? OR mac LIKE ? OR IFNULL(hostname,'') LIKE ? OR IFNULL(vendor,'') LIKE ? OR IFNULL(label,'') LIKE ?) ORDER BY online DESC, ip LIMIT ?",
                        (nid, *([like(q)] * 5), limit))
        rows = [with_category(r) for r in rows]
        return [r for r in rows if r["category"] == category] if category else rows

    @app.get("/api/device-categories")
    def device_categories(role=Depends(auth)):
        return fingerprint.CATEGORY_CHOICES

    @app.patch("/api/devices/{did}")
    def patch_device(did: int, body: DevicePatch, role=Depends(admin)):
        if not db.one("SELECT id FROM devices WHERE id=?", (did,)):
            raise HTTPException(404)
        for col, val in (("owner", body.owner), ("label", body.label)):
            if val is not None:
                db.execute(f"UPDATE devices SET {col}=? WHERE id=?", (val, did))
        if body.trusted is not None:
            db.execute("UPDATE devices SET trusted=? WHERE id=?", (int(body.trusted), did))
        if body.user_type is not None:
            if body.user_type and body.user_type not in fingerprint.CATEGORY_CHOICES:
                raise HTTPException(400, "Categoría no válida")
            db.execute("UPDATE devices SET user_type=NULLIF(?,'') WHERE id=?", (body.user_type, did))
        db.audit(role, "device_updated", did, body.model_dump_json(exclude_none=True))
        return {"ok": True}

    @app.get("/api/connections")
    def connections(q: str = "", direction: str = "", show_all: bool = Query(False, alias="all"), limit: int = Query(500, le=5000), role=Depends(auth)):
        """Por defecto oculta el ruido (escuchas locales, LAN/multicast, DNS, NTP, DHCP, mDNS, SSDP, NetBIOS) y traduce IP -> dominio/servicio."""
        fetch = limit if show_all else min(limit * 6, 20000)
        rows = db.query("SELECT c.*, c.ts_last-c.ts_first AS duration, n.domain AS domain FROM connections c LEFT JOIN ip_names n ON n.ip=c.raddr "
                        "WHERE (c.raddr LIKE ? OR IFNULL(c.process,'') LIKE ? OR IFNULL(n.domain,'') LIKE ?) AND (?='' OR c.direction=?) ORDER BY c.ts_last DESC LIMIT ?",
                        (like(q), like(q), like(q), direction, direction, fetch))
        if not show_all:
            rows = [r for r in rows if not services.is_noise(r)]
        rows = rows[:limit]
        devs, acts, custom = device_map(), cfg.get("service_actions") or {}, cfg.get("custom_services", [])
        for r in rows:
            svc = services.classify_domain(r.get("domain") or "", custom)
            r["service"] = svc["label"] if svc else ""
            r["device_name"] = dname(devs, r["device_id"])[0] if r.get("device_id") else next((d["display_name"] for d in devs.values() if d["is_self"]), "Este equipo")
            r["level"] = "high" if r["rport"] in RISKY_PORTS else "medium" if svc and svc["key"] in acts else "info"  # criticidad por color
        return rows

    @app.get("/api/domains")
    def domains(q: str = "", known: bool = False, limit: int = Query(500, le=5000), role=Depends(auth)):
        return db.query("SELECT d.*, IFNULL(v.ip,'') device_ip FROM domains d LEFT JOIN devices v ON v.id=d.device_id WHERE d.domain LIKE ? AND (?=0 OR d.category!='sin clasificar') ORDER BY d.last_seen DESC LIMIT ?",
                        (like(q), int(known), limit))

    @app.post("/api/domains")
    def ingest_domain(body: DomainBody, role=Depends(admin)):
        mon.telemetry.ingest_domain(body.domain, body.device_id, "api")
        return {"ok": True}

    @app.get("/api/applications")
    def applications(role=Depends(auth)):
        confirmed = db.query("SELECT process app, COUNT(DISTINCT raddr) destinations, SUM(count) observations, MAX(ts_last) last_seen FROM connections WHERE process IS NOT NULL AND direction!='listen' GROUP BY process ORDER BY observations DESC")
        for r in confirmed:
            r["name"] = KNOWN_APPS.get(r["app"].lower(), r["app"])
            r["confidence"] = "confirmada (proceso del endpoint)"
        est = db.query("SELECT rport, COUNT(DISTINCT raddr) destinations, SUM(count) observations, MAX(ts_last) last_seen FROM connections WHERE direction='outbound' AND rport>0 GROUP BY rport ORDER BY observations DESC LIMIT 30")
        est = [{"app": PORT_SERVICES.get(r["rport"], f"puerto {r['rport']}"), "name": PORT_SERVICES.get(r["rport"], f"puerto {r['rport']}"), "destinations": r["destinations"],
                "observations": r["observations"], "last_seen": r["last_seen"], "confidence": "estimada (por puerto)"} for r in est]
        return confirmed + est

    @app.get("/api/processes")
    def processes(role=Depends(auth)):
        rows = db.query("SELECT * FROM processes ORDER BY suspicious DESC, last_seen DESC LIMIT 500")
        me = next((d["display_name"] for d in device_map().values() if d["is_self"]), "Este equipo")
        for r in rows:
            r["criticality"] = "alta" if r["suspicious"] else "baja"
            r["device"] = me
        return rows

    @app.get("/api/traffic")
    def traffic(minutes: int = Query(30, ge=1, le=1440), role=Depends(auth)):
        return db.query("SELECT ts,rx_rate,tx_rate FROM traffic WHERE ts>strftime('%s','now')-? ORDER BY ts", (minutes * 60,))

    @app.get("/api/traffic/summary")
    def traffic_summary(role=Depends(auth)):
        now = time.time()
        rows = db.query("SELECT ts,interface,rx_bytes,tx_bytes FROM traffic WHERE ts>? ORDER BY ts", (int(now) - 7 * 86400 - 600,))
        out = usage.summarize(rows, now)
        out["interface"] = mon.sig.get("interface", "")
        return out

    @app.get("/api/activity")
    def activity(hours: int = Query(24, ge=1, le=720), role=Depends(auth)):
        """Servicios reconocidos (YouTube, Netflix, adultos...) vistos por dispositivo. Solo dominios, nunca contenido."""
        since = int(time.time()) - hours * 3600
        rows = db.query("SELECT d.domain, d.device_id, d.count, d.first_seen, d.last_seen, IFNULL(v.ip,'') device_ip, IFNULL(v.hostname,'') hostname, IFNULL(v.label,'') label "
                        "FROM domains d LEFT JOIN devices v ON v.id=d.device_id WHERE d.last_seen>? AND d.category!='sin clasificar'", (since,))
        agg = {}
        for r in rows:
            svc = services.classify_domain(r["domain"])
            if not svc or not svc["strong"]:
                continue
            a = agg.setdefault((svc["key"], r["device_id"]), {"key": svc["key"], "service": svc["label"], "category": svc["category"], "device_id": r["device_id"],
                                                               "device_ip": r["device_ip"], "device": r["label"] or r["hostname"] or r["device_ip"] or "Dispositivo no identificado",
                                                               "hits": 0, "first_seen": r["first_seen"], "last_seen": r["last_seen"], "domains": []})
            a["hits"] += r["count"]
            a["first_seen"], a["last_seen"] = min(a["first_seen"], r["first_seen"]), max(a["last_seen"], r["last_seen"])
            if len(a["domains"]) < 4 and r["domain"] not in a["domains"]:
                a["domains"].append(r["domain"])
        others = db.one("SELECT COUNT(*) c FROM domains d JOIN devices v ON v.id=d.device_id WHERE v.is_self=0")["c"] > 0
        return {"hours": hours, "items": sorted(agg.values(), key=lambda a: -a["last_seen"]), "watch": cfg.get("watch_services", []),
                "options": services.watch_options(), "sees_other_devices": others}

    # ------------------------------------------------------------ v2: resumen, grupos, feed, firewall
    EVENTOS = {"discovered": ("Conexión", "ok", "El dispositivo apareció en la red."), "online": ("Reconexión", "info", "El dispositivo volvió a conectarse a la red."),
               "offline": ("Desconexión", "warn", "El dispositivo dejó de verse en la red."), "ip_changed": ("Cambio de IP", "info", "El dispositivo cambió de dirección IP.")}
    _cache = {}

    def cached(key, ttl, fn):
        t = time.time()
        if key not in _cache or t - _cache[key][0] > ttl:
            _cache[key] = (t, fn())
        return _cache[key][1]

    def presence(devs, limit):
        rows = db.query("SELECT a.ts,a.event,a.detail,a.device_id FROM device_activity a WHERE a.event IN ('discovered','online','offline','ip_changed') ORDER BY a.ts DESC LIMIT ?", (limit * 3,))
        out = []
        for r in rows:
            if r["device_id"] not in devs:
                continue
            ev, lvl, txt = EVENTOS[r["event"]]
            n, ip = dname(devs, r["device_id"])
            out.append({"ts": r["ts"], "ip": ip, "name": n, "event": ev, "level": lvl, "detail": txt + (f" {r['detail']}" if r["detail"] and r["event"] == "ip_changed" else "")})
        return out[:limit]

    def feed_items(devs, limit):
        out = presence(devs, limit)
        for r in db.query("SELECT * FROM domain_visits ORDER BY ts_start DESC LIMIT ?", (limit,)):
            n, ip = dname(devs, r["device_id"])
            first = r["nth"] == 1
            out.append({"ts": r["ts_start"], "ip": ip, "name": n, "event": "Inicio en dominio" if first else "Retención en dominio",
                        "level": "warn" if (cfg.get("service_actions") or {}).get(r["gkey"]) else "info",
                        "detail": f"{r['glabel']} ({r['domain']}): " + ("primera visita observada." if first else f"regresó tras más de 30 min (visita n.º {r['nth']}).")})
        for r in db.query("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)):
            n, ip = dname(devs, r["device_id"]) if r["device_id"] else ("Red", "")
            out.append({"ts": r["ts"], "ip": ip, "name": n, "event": "Alerta", "level": r["severity"], "detail": f"{r['title']} — {r['description'] or ''}"[:300]})
        return sorted(out, key=lambda x: -x["ts"])[:limit]

    @app.get("/api/feed")
    def feed(limit: int = Query(40, le=200), role=Depends(auth)):
        return feed_items(device_map(), limit)

    @app.get("/api/dashboard")
    def dashboard(role=Depends(auth)):
        now, net = int(time.time()), mon.network
        devs = device_map()
        acts, custom = cfg.get("service_actions") or {}, cfg.get("custom_services", [])
        hot = [r for r in db.query("SELECT gkey, glabel, COUNT(*) n FROM domain_visits WHERE ts_last>? GROUP BY gkey", (now - 3600,)) if r["gkey"] in acts]
        tr = db.one("SELECT * FROM traffic ORDER BY ts DESC LIMIT 1")
        day0 = int(datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

        def usage_today():
            return usage.summarize(db.query("SELECT ts,interface,rx_bytes,tx_bytes FROM traffic WHERE ts>? ORDER BY ts", (day0 - 120,)), time.time())
        u = cached("usage", 10, usage_today)
        selfd = next((d for d in devs.values() if d["is_self"]), None)
        others = db.one("SELECT COUNT(DISTINCT v.device_id) c FROM domain_visits v JOIN devices d ON d.id=v.device_id WHERE d.is_self=0")["c"]
        sev = db.one("SELECT COUNT(*) c FROM alerts WHERE status='open' AND severity IN ('medium','high')")["c"]
        return {"version": __version__, "connected": mon.sig.get("connected", False), "signal": mon.sig, "network": net, "scanning": mon.scanning,
                "endpoint": {"name": selfd["display_name"] if selfd else "Este equipo", "ip": mon.sig.get("ip", ""), "connected": mon.sig.get("connected", False)},
                "devices": {"total": len(devs), "online": sum(1 for d in devs.values() if d["online"])},
                "firewall": {"rules": len(acts) + len(custom), "blocking": sum(1 for a in acts.values() if a == "bloquear"), "hits": sum(r["n"] for r in hot), "services": [r["glabel"] for r in hot]},
                "alerts": {"open": db.one("SELECT COUNT(*) c FROM alerts WHERE status='open'")["c"], "serious": sev},
                "traffic": tr, "usage": {"last_hour": u["last_hour"], "today": u["today"]},
                "presence": presence(devs, 14), "feed": feed_items(devs, 30),
                "visibility": {"other_devices_with_activity": others, "devices_total": len(devs)},
                "control_enabled": cfg["control_enabled"], "dry_run": cfg["control_dry_run"]}

    @app.get("/api/groups")
    def groups(hours: int = Query(24, ge=1, le=720), limit: int = Query(80, le=300), role=Depends(auth)):
        """Dominios y apps sin repeticiones: cada grupo lista por dispositivo sus últimas 10 visitas (separadas por 30 min)."""
        devs, since = device_map(), int(time.time()) - hours * 3600
        agg = {}
        for r in db.query("SELECT * FROM domain_visits WHERE ts_last>? ORDER BY ts_start DESC LIMIT 20000", (since,)):
            g = agg.setdefault(r["gkey"], {"key": r["gkey"], "label": r["glabel"], "kind": r["gkind"], "visits": 0, "last": 0, "devices": {}})
            g["visits"] += 1
            g["last"] = max(g["last"], r["ts_last"])
            d = g["devices"].setdefault(r["device_id"], {"device_id": r["device_id"], "name": dname(devs, r["device_id"])[0], "ip": dname(devs, r["device_id"])[1], "count": 0, "visits": []})
            d["count"] += 1
            if len(d["visits"]) < 10:
                d["visits"].append({"start": r["ts_start"], "end": r["ts_last"], "domain": r["domain"], "nth": r["nth"]})
        out = sorted(agg.values(), key=lambda g: (g["kind"] != "app", -g["last"]))[:limit]
        for g in out:
            g["devices"] = sorted(g["devices"].values(), key=lambda d: -d["visits"][0]["start"])
        return out

    @app.get("/api/device-services")
    def device_services(role=Depends(auth)):
        devs = device_map()
        by = {}
        for r in db.query("SELECT device_id, glabel, COUNT(*) visits, MAX(ts_last) last FROM domain_visits WHERE gkind='app' GROUP BY device_id, gkey ORDER BY last DESC"):
            by.setdefault(r["device_id"], []).append({"label": r["glabel"], "kind": "Servicio", "visits": r["visits"], "last": r["last"]})
        tools = [{"label": KNOWN_APPS.get(r["app"].lower(), r["app"]), "kind": "Herramienta (proceso)", "visits": r["observations"], "last": r["last_seen"]} for r in applications(role) if r["confidence"].startswith("confirmada")]
        out = []
        for d in sorted(devs.values(), key=lambda d: (-d["online"], d["display_name"])):
            items = by.get(d["id"], []) + (tools if d["is_self"] else [])
            out.append({"id": d["id"], "name": d["display_name"], "ip": d["ip"], "category": d["category"], "online": d["online"], "items": items})
        return out

    @app.get("/api/analytics/device-peaks")
    def device_peaks(days: int = Query(7, ge=1, le=30), role=Depends(auth)):
        devs, since, hours = device_map(), int(time.time()) - days * 86400, {}
        for r in db.query("SELECT device_id, ts_start FROM domain_visits WHERE ts_start>?", (since,)):
            hours.setdefault(r["device_id"], [0] * 24)[datetime.fromtimestamp(r["ts_start"]).hour] += 1
        return [{"name": dname(devs, i)[0], "ip": dname(devs, i)[1], "hours": h, "peak_hour": h.index(max(h)), "total": sum(h)} for i, h in sorted(hours.items(), key=lambda x: -sum(x[1]))]

    class FwAction(BaseModel):
        action: Literal["permitir", "alertar", "bloquear"]

    class FwCustom(BaseModel):
        label: str = Field(..., min_length=1, max_length=40)
        pattern: str = Field(..., min_length=3, max_length=200)

    def fw_domains(key):
        if key in services.SERVICES:
            return list(services.SERVICES[key]["strong"])
        return [c["pattern"] for c in cfg.get("custom_services", []) if c["key"] == key]

    def fw_enforce(key, block, actor):
        """Intenta bloquear/desbloquear los dominios del servicio mediante el adaptador de control. Nunca finge éxito."""
        done, err = 0, ""
        for d in fw_domains(key):
            try:
                mon.control.apply("block_domain" if block else "unblock_domain", d, actor, True, None, mon.network["id"] if mon.network else None)
                done += 1
            except ControlError as e:
                err = str(e)
                break
        return {"enforced": done > 0 and not err, "detail": err or f"Aplicado a {done} dominios mediante el adaptador."}

    @app.get("/api/firewall")
    def firewall(role=Depends(auth)):
        now, acts = int(time.time()), cfg.get("service_actions") or {}
        caps = mon.control.capabilities()["actions"]["block_domain"]
        seen = {r["gkey"]: r for r in db.query("SELECT gkey, COUNT(*) visits, MAX(ts_last) last FROM domain_visits WHERE ts_last>? GROUP BY gkey", (now - 86400,))}
        items = [{"key": k, "label": s["label"], "category": s["category"], "custom": False} for k, s in services.SERVICES.items()]
        items += [{"key": c["key"], "label": c["label"], "category": "Personalizado", "custom": True, "pattern": c["pattern"]} for c in cfg.get("custom_services", [])]
        for it in items:
            it["action"] = acts.get(it["key"], "permitir")
            it["visits"], it["last"] = seen.get(it["key"], {}).get("visits", 0), seen.get(it["key"], {}).get("last")
        return {"items": items, "can_block": caps["supported"], "block_reason": caps["reason"], "control_enabled": cfg["control_enabled"], "dry_run": cfg["control_dry_run"]}

    @app.put("/api/firewall/{key}")
    def fw_set(key: str, body: FwAction, role=Depends(admin)):
        if key not in services.SERVICES and key not in {c["key"] for c in cfg.get("custom_services", [])}:
            raise HTTPException(404, "Servicio no encontrado")
        acts = dict(cfg.get("service_actions") or {})
        prev = acts.get(key, "permitir")
        if body.action == "permitir":
            acts.pop(key, None)
        else:
            acts[key] = body.action
        cfg["service_actions"] = acts
        config.save(cfg)
        mon.publish_watch()
        res = fw_enforce(key, body.action == "bloquear", role) if "bloquear" in (body.action, prev) else {"enforced": False, "detail": ""}
        db.audit(role, "firewall_set", key, f"{prev} -> {body.action}; {res['detail']}")
        return {"ok": True, "action": body.action, **res}

    @app.post("/api/firewall/custom")
    def fw_custom_add(body: FwCustom, role=Depends(admin)):
        raw = body.pattern.strip().lower()
        host = (urlparse(raw).hostname if "://" in raw else raw.split("/")[0]) or ""
        host = host.removeprefix("www.").removeprefix("*.").strip(".")
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", host):
            raise HTTPException(400, "Escribe un dominio o link válido (por ejemplo ejemplo.com). Cubre también sus subdominios.")
        key = "c_" + re.sub(r"[^a-z0-9]+", "-", host)
        custom = list(cfg.get("custom_services", []))
        if any(c["key"] == key for c in custom) or len(custom) >= 50:
            raise HTTPException(400, "Esa regla ya existe o se alcanzó el máximo (50).")
        custom.append({"key": key, "label": body.label.strip(), "pattern": host})
        cfg["custom_services"] = custom
        config.save(cfg)
        mon.publish_watch()
        db.audit(role, "firewall_custom_add", key, host)
        return {"ok": True, "key": key}

    @app.delete("/api/firewall/custom/{key}")
    def fw_custom_del(key: str, role=Depends(admin)):
        custom = cfg.get("custom_services", [])
        if not any(c["key"] == key for c in custom):
            raise HTTPException(404)
        if (cfg.get("service_actions") or {}).get(key) == "bloquear":
            fw_enforce(key, False, role)
        cfg["custom_services"] = [c for c in custom if c["key"] != key]
        acts = dict(cfg.get("service_actions") or {})
        acts.pop(key, None)
        cfg["service_actions"] = acts
        config.save(cfg)
        mon.publish_watch()
        db.audit(role, "firewall_custom_del", key)
        return {"ok": True}

    @app.get("/api/alerts")
    def alerts(status: str = "", limit: int = Query(300, le=2000), role=Depends(auth)):
        rows = db.query("SELECT a.*, IFNULL(d.ip,'') device_ip FROM alerts a LEFT JOIN devices d ON d.id=a.device_id WHERE (?='' OR a.status=?) ORDER BY a.ts DESC LIMIT ?", (status, status, limit))
        devs = device_map()
        for r in rows:
            r["device_name"] = dname(devs, r["device_id"])[0] if r.get("device_id") else ""
            try:
                r["evidence"] = json.loads(r["evidence"])
            except (TypeError, ValueError):
                pass
        return rows

    @app.patch("/api/alerts/{aid}")
    def patch_alert(aid: int, body: AlertPatch, role=Depends(admin)):
        if not db.one("SELECT id FROM alerts WHERE id=?", (aid,)):
            raise HTTPException(404)
        db.execute("UPDATE alerts SET status=? WHERE id=?", (body.status, aid))
        db.audit(role, "alert_status", aid, body.status)
        return {"ok": True}

    @app.get("/api/control/capabilities")
    def caps(role=Depends(auth)):
        return mon.control.capabilities()

    @app.get("/api/control/policies")
    def policies(role=Depends(auth)):
        return db.query("SELECT * FROM policies ORDER BY ts DESC LIMIT 300")

    @app.post("/api/control/apply")
    def apply(body: ControlBody, role=Depends(admin)):
        try:
            return mon.control.apply(body.action, body.target, role, body.confirm, body.minutes, mon.network["id"] if mon.network else None)
        except ControlError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/investigation/{did}")
    def investigation(did: int, role=Depends(auth)):
        dev = db.one("SELECT * FROM devices WHERE id=?", (did,))
        if not dev:
            raise HTTPException(404)
        tl = [{"ts": r["ts"], "type": "actividad", "text": f"{r['event']} {r['detail'] or ''}"} for r in db.query("SELECT * FROM device_activity WHERE device_id=?", (did,))]
        tl += [{"ts": r["ts"], "type": "alerta", "level": r["severity"], "text": f"[{r['severity']}] {r['title']} ({r['rule']}): {r['description'] or ''}"} for r in db.query("SELECT * FROM alerts WHERE device_id=?", (did,))]
        tl += [{"ts": r["last_seen"], "type": "dominio", "text": f"{r['domain']} x{r['count']} ({r['category']})"} for r in db.query("SELECT * FROM domains WHERE device_id=?", (did,))]
        for r in db.query("SELECT * FROM domain_visits WHERE device_id=? ORDER BY ts_start DESC LIMIT 200", (did,)):
            tl.append({"ts": r["ts_start"], "type": "inicio en dominio" if r["nth"] == 1 else "retención en dominio",
                       "text": f"{r['glabel']} ({r['domain']}): " + ("primera visita observada." if r["nth"] == 1 else f"el dispositivo regresó (visita n.º {r['nth']}, pasaron más de 30 min desde la anterior)."),
                       "level": "warn" if (cfg.get("service_actions") or {}).get(r["gkey"]) else "info"})
        if dev["is_self"]:
            tl += [{"ts": r["last_seen"], "type": "proceso", "level": "high", "text": f"Proceso {r['name']} con actividad de red: {r['reason']}"} for r in db.query("SELECT * FROM processes WHERE suspicious=1")]
        conns = db.query("SELECT * FROM connections WHERE device_id=? ORDER BY ts_last DESC LIMIT 300", (did,))
        tl += [{"ts": r["ts_first"], "type": "conexión", "text": f"{r['proto']} {r['raddr']}:{r['rport']} {r['process'] or ''} ({r['direction']})"} for r in conns]
        return {"device": with_category(dev), "timeline": sorted(tl, key=lambda x: -x["ts"])[:500]}

    @app.get("/api/investigation/{did}/export")
    def export_ev(did: int, role=Depends(admin)):
        ev = reports.evidence_json(db, did)
        if ev is None:
            raise HTTPException(404)
        db.audit(role, "evidence_exported", did)
        return Response(json.dumps(ev, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename=evidencia_{did}.json"})

    @app.get("/api/analytics/hourly")
    def hourly(days: int = Query(7, ge=1, le=90), role=Depends(auth)):
        rows = db.query("SELECT CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) hour, AVG(rx_rate+tx_rate) avg_rate, MAX(rx_rate+tx_rate) peak_rate, COUNT(*) samples FROM traffic WHERE ts>strftime('%s','now')-? GROUP BY hour ORDER BY hour", (days * 86400,))
        have = {r["hour"]: r for r in rows}
        return [have.get(h, {"hour": h, "avg_rate": 0, "peak_rate": 0, "samples": 0}) for h in range(24)]

    @app.get("/api/sniffer")
    def sniffer_status(role=Depends(auth)):
        import time as _t
        st = db.get_state()
        c = json.loads(st.get("counters") or "{}")
        hb = int(st.get("heartbeat") or 0)
        running = st.get("status") == "running" and _t.time() - hb < 20
        return {"enabled": cfg["sniffer_enabled"], "promiscuous": cfg["sniffer_promiscuous"], "running": running, "status": st.get("status", "stopped"),
                "detail": st.get("status_detail", ""), "iface": st.get("iface", ""), "heartbeat": hb, "counters": c,
                "sees_other_devices_traffic": c.get("foreign_unicast", 0) > 0,
                "fix": "Ejecuta ./scripts/enable-sniffer.sh (una sola vez) y reinicia con ./stop.sh && ./start.sh" if st.get("status") == "no_permission" else ""}

    @app.get("/api/events")
    def events(kind: str = "", limit: int = Query(300, le=3000), role=Depends(auth)):
        return db.query("SELECT * FROM net_events WHERE (?='' OR kind=?) ORDER BY ts_last DESC LIMIT ?", (kind, kind, limit))

    @app.get("/api/recording")
    def rec_status(role=Depends(auth)):
        return {"recording": mon.recording_since is not None, "since": mon.recording_since, "last_file": mon.last_recording}

    @app.post("/api/recording/start")
    def rec_start(role=Depends(admin)):
        import time as _t
        mon.recording_since = int(_t.time())
        db.audit(role, "recording_started")
        return {"recording": True, "since": mon.recording_since}

    @app.post("/api/recording/stop")
    def rec_stop(role=Depends(admin)):
        if mon.recording_since is None:
            raise HTTPException(409, "No hay grabación en curso")
        path = mon.save_recording()
        db.audit(role, "recording_saved", path)
        return {"recording": False, "file": str(path)}

    @app.get("/api/recording/current.json")
    def rec_current(role=Depends(auth)):
        return Response(json.dumps(reports.session_json(db, mon.recording_since or 0), indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=sesion.json"})

    @app.get("/api/audit")
    def audit(limit: int = Query(300, le=2000), role=Depends(auth)):
        return db.query("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,))

    @app.get("/api/integrations")
    def integrations(role=Depends(auth)):
        from .integrations.tshark import TsharkDNS
        c = mon.control.capabilities()
        return {"tshark": {"installed": TsharkDNS.available(), "enabled": cfg["integrations"]["tshark"]["enabled"]},
                "adguard": {"enabled": cfg["integrations"]["adguard"]["enabled"], **c["adapters"].get("adguard", {"available": False, "reason": "deshabilitado"})},
                "nftables": {"enabled": cfg["integrations"]["nftables"]["enabled"], **c["adapters"].get("nftables", {"available": False, "reason": "deshabilitado"})},
                "zeek": {"enabled": False, "available": False, "reason": "Adaptador no implementado en v1.0.0 (ver docs/LIMITATIONS.md)"},
                "ntopng": {"enabled": False, "available": False, "reason": "Adaptador no implementado en v1.0.0"},
                "arkime": {"enabled": False, "available": False, "reason": "Adaptador no implementado en v1.0.0"},
                "opnsense_pfsense": {"enabled": False, "available": False, "reason": "Adaptador no implementado en v1.0.0"}}

    @app.get("/api/settings")
    def get_settings(role=Depends(auth)):
        m = config.masked(cfg)
        if role != "admin":
            m.pop("integrations", None)
        m.pop("admin_token", None)
        m.pop("viewer_token", None)
        return m

    @app.patch("/api/settings")
    def patch_settings(body: SettingsPatch, role=Depends(admin)):
        d = body.model_dump(exclude_none=True)
        for k in ("control_enabled", "control_dry_run", "scan_interval", "port_scan", "retention_days", "sniffer_enabled", "sniffer_promiscuous", "probe_discovery"):
            if k in d:
                cfg[k] = d[k]
        if "watch_services" in d:
            cfg["watch_services"] = [k for k in dict.fromkeys(d["watch_services"]) if k in services.SERVICES]
        if "adguard" in d:
            for k, v in d["adguard"].items():
                cfg["integrations"]["adguard"][k] = v
        if "tshark_enabled" in d:
            cfg["integrations"]["tshark"]["enabled"] = d["tshark_enabled"]
        if "nftables_enabled" in d:
            cfg["integrations"]["nftables"]["enabled"] = d["nftables_enabled"]
        config.save(cfg)
        if {"sniffer_enabled", "sniffer_promiscuous", "probe_discovery", "watch_services", "scan_interval"} & d.keys():
            mon.publish_sniffer_state()
        if "sniffer_enabled" in d or "sniffer_promiscuous" in d:
            if cfg["sniffer_enabled"]:
                mon.restart_sniffer()
            else:
                mon.stop_sniffer()
                db.set_state("status", "disabled")
        safe = {k: ("***" if "password" in k else v) for k, v in d.items()}
        db.audit(role, "settings_changed", "", json.dumps(safe, default=str))
        return {"ok": True}

    @app.get("/api/reports/html")
    def report_html(network_id: Optional[int] = None, role=Depends(auth)):
        return Response(reports.build_html(db, network_id), media_type="text/html")

    @app.get("/api/reports/{kind}.csv")
    def report_csv(kind: Literal["devices", "alerts", "connections", "domains"], role=Depends(auth)):
        rows = db.query({"devices": "SELECT * FROM devices", "alerts": "SELECT * FROM alerts", "connections": "SELECT * FROM connections ORDER BY ts_last DESC LIMIT 20000",
                         "domains": "SELECT * FROM domains"}[kind])
        return Response(reports.to_csv(rows), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={kind}.csv"})

    if DASH.exists():
        app.mount("/", StaticFiles(directory=str(DASH), html=True), name="dashboard")
    return app
