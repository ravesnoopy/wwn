"""Bucle de monitoreo en segundo plano: red actual, escaneos, telemetría, expiraciones, informes y retención."""
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from . import config, detection, inventory, netinfo, profiles, reports, scanner
from .control import Control
from .integrations.adguard import AdGuardAdapter
from .integrations.tshark import TsharkDNS
from .telemetry import Telemetry

log = logging.getLogger("whitewidow")


class Monitor:
    def __init__(self, db, cfg):
        self.db, self.cfg = db, cfg
        self.telemetry = Telemetry(db)
        self.control = Control(db, cfg)
        self.sig = {"connected": False}
        self.network = None
        self.self_device_id = None
        self.last_sig = None
        self.scanning = False
        self.tasks, self.tshark = [], None
        self.last_scan = 0.0
        self.last_report = time.time()
        self.recording_since = None
        self.last_recording = None
        self.sniffer_proc = None
        self.sniffer_next_try = 0.0

    # ---- red actual ----
    def refresh_network(self):
        sig = netinfo.detect()
        self.sig = sig
        if not sig.get("connected"):
            if self.network is not None:
                self.db.audit("system", "network_disconnected", self.network["name"])
            self.network = None
            self.last_sig = None
            self.publish_sniffer_state()
            return False
        s = netinfo.signature(sig)
        if s == self.last_sig and self.network:
            return False
        net, is_new, sc = profiles.identify(self.db, sig, set(netinfo.neighbors().values()))
        changed = self.network is None or self.network["id"] != net["id"]
        self.network, self.last_sig = net, s
        self.publish_sniffer_state()
        self.db.audit("system", "network_new" if is_new else "network_recognized", net["name"], f"puntaje={sc} subred={sig['subnet']} gw={sig.get('gateway')}")
        log.info("Red %s: %s", "NUEVA" if is_new else "reconocida", net["name"])
        if changed:
            self.last_scan = 0.0
        return True

    # ---- escucha pasiva (proceso aparte con cap_net_raw) ----
    def publish_sniffer_state(self):
        sig, net = self.sig, self.network
        ok = bool(sig.get("connected") and net)
        for k, v in (("iface", sig.get("interface", "") if ok else ""), ("network_id", net["id"] if ok else ""), ("self_ip", sig.get("ip", "")),
                     ("self_mac", sig.get("iface_mac", "")), ("gateway_ip", sig.get("gateway", "")), ("subnet", sig.get("subnet", "")),
                     ("want_promisc", "1" if self.cfg.get("sniffer_promiscuous") else "0"),
                     ("probe_enabled", "1" if self.cfg.get("probe_discovery", True) else "0"), ("probe_interval", self.cfg["scan_interval"])):
            self.db.set_state(k, v)
        self.publish_watch()

    def publish_watch(self):
        """Política por servicio y reglas propias: el proceso de escucha las lee de la base de datos."""
        acts = self.cfg.get("service_actions")
        if acts is None:
            acts = {k: "alertar" for k in self.cfg.get("watch_services", [])}
        self.db.set_state("service_actions", json.dumps(acts))
        self.db.set_state("watch_services", json.dumps([k for k, a in acts.items() if a in ("alertar", "bloquear")]))
        self.db.set_state("custom_services", json.dumps(self.cfg.get("custom_services", [])))

    def sniffer_python(self):
        capable = Path(sys.prefix) / "bin" / "python-ww"  # copia con cap_net_raw creada por enable-sniffer.sh
        return str(capable) if capable.exists() else sys.executable

    def start_sniffer(self):
        if not self.cfg.get("sniffer_enabled", True) or (self.sniffer_proc and self.sniffer_proc.poll() is None):
            return
        if time.time() < self.sniffer_next_try:
            return
        d = config.data_dir() / "logs"
        d.mkdir(exist_ok=True)
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent))
        self.publish_sniffer_state()
        self.sniffer_proc = subprocess.Popen([self.sniffer_python(), "-m", "whitewidow_net.sniffer"], env=env,
                                             stdout=open(d / "sniffer.log", "ab"), stderr=subprocess.STDOUT)
        self.sniffer_next_try = time.time() + 10

    def supervise_sniffer(self):
        p = self.sniffer_proc
        if p is not None and p.poll() is not None:
            if p.returncode == 3:  # sin permiso: no reintentar en bucle
                self.sniffer_next_try = time.time() + 3600
            self.sniffer_proc = None
        if self.cfg.get("sniffer_enabled", True) and self.sniffer_proc is None:
            self.start_sniffer()

    def stop_sniffer(self):
        p = self.sniffer_proc
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        self.sniffer_proc = None

    def restart_sniffer(self):
        self.stop_sniffer()
        self.sniffer_next_try = 0.0
        self.start_sniffer()

    def mark_stale_offline(self):
        """Dispositivos no vistos en mucho tiempo (por escucha o escaneo) pasan a 'fuera'."""
        limit = max(3 * self.cfg["scan_interval"], 1800)
        for d in self.db.query("SELECT id FROM devices WHERE online=1 AND last_seen<? AND is_self=0", (int(time.time()) - limit,)):
            self.db.execute("UPDATE devices SET online=0 WHERE id=?", (d["id"],))
            self.db.execute("INSERT INTO device_activity(device_id,ts,event,detail) VALUES(?,?,?,?)", (d["id"], int(time.time()), "offline", "sin actividad observada"))

    # ---- escaneo ----
    def run_scan(self, force_mode=None):
        if not self.network or self.scanning:
            return None
        self.scanning = True
        try:
            net = self.db.one("SELECT * FROM networks WHERE id=?", (self.network["id"],))
            active = bool(net["authorized"]) and force_mode != "passive"
            mode = "active" if active else "passive"
            if active:  # el proceso de escucha (con cap_net_raw) hace el sondeo ARP/mDNS/SSDP en paralelo
                self.db.set_state("probe_request", f"{time.time():.3f}")
            results = scanner.scan(self.sig["subnet"], max_hosts=self.cfg["max_scan_hosts"], port_scan=self.cfg["port_scan"], active=active)
            if not any(r["ip"] == self.sig["ip"] for r in results):
                results.append({"ip": self.sig["ip"], "mac": self.sig.get("iface_mac", ""), "hostname": "", "ports": []})
            new = inventory.persist(self.db, net, results, self.sig, mode, mark_offline=active)
            me = self.db.one("SELECT id FROM devices WHERE network_id=? AND ip=?", (net["id"], self.sig["ip"]))
            self.self_device_id = me["id"] if me else None
            self.last_scan = time.time()
            return {"mode": mode, "found": len(results), "new": new}
        finally:
            self.scanning = False

    # ---- tareas ----
    async def _loop(self, fn, interval, name):
        while True:
            try:
                await asyncio.to_thread(fn)
            except Exception:  # un fallo no debe detener el monitoreo
                log.exception("Error en tarea %s", name)
            await asyncio.sleep(interval)

    def _t_network(self):
        self.refresh_network()

    def _t_scan(self):
        if not self.network:
            return
        interval = self.cfg["scan_interval"] if self.network["authorized"] else self.cfg["passive_interval"]
        if time.time() - self.last_scan >= interval:
            self.run_scan()

    def _t_telemetry(self):
        nid = self.network["id"] if self.network else None
        self.telemetry.collect_connections(nid, self.self_device_id)
        if self.sig.get("interface"):
            self.telemetry.sample_traffic(self.sig["interface"], nid)

    def _t_maintenance(self):
        self.control.expire()
        self.mark_stale_offline()
        self.supervise_sniffer()
        self.db.purge(self.cfg["retention_days"])
        ag = self.cfg["integrations"]["adguard"]
        if ag["enabled"] and ag["url"]:
            try:
                for e in AdGuardAdapter(ag).query_log(100):
                    dev = self.db.one("SELECT id FROM devices WHERE ip=?", (e["client"],))
                    self.telemetry.ingest_domain(e["domain"], dev["id"] if dev else 0, "adguard")
            except Exception as e:
                log.warning("AdGuard: %s", e)
        if time.time() - self.last_report >= self.cfg["report_interval_hours"] * 3600:
            self.write_report()

    def write_report(self):
        d = config.data_dir() / "reports"
        d.mkdir(exist_ok=True)
        p = d / f"informe_{time.strftime('%Y%m%d_%H%M%S')}.html"
        p.write_text(reports.build_html(self.db), encoding="utf-8")
        self.last_report = time.time()
        return p

    def save_recording(self):
        import json as _j
        d = config.data_dir() / "recordings"
        d.mkdir(exist_ok=True)
        p = d / f"sesion_{time.strftime('%Y%m%d_%H%M%S')}.json"
        p.write_text(_j.dumps(reports.session_json(self.db, self.recording_since or 0), indent=2, default=str), encoding="utf-8")
        self.recording_since, self.last_recording = None, str(p)
        return p

    def start_integrations(self):
        t = self.cfg["integrations"]["tshark"]
        if t["enabled"] and TsharkDNS.available():
            def on_q(src, dom):
                dev = self.db.one("SELECT id FROM devices WHERE ip=?", (src,))
                self.telemetry.ingest_domain(dom, dev["id"] if dev else 0, "tshark")
            self.tshark = TsharkDNS(t["interface"] or self.sig.get("interface", ""), on_q)
            if not self.tshark.start():
                log.warning("TShark no pudo iniciar (interfaz o permisos)")

    def start(self):
        self.refresh_network()
        self.start_integrations()
        self.start_sniffer()
        loop = asyncio.get_running_loop()
        for fn, iv, nm in ((self._t_network, 10, "red"), (self._t_scan, 5, "escaneo"),
                           (self._t_telemetry, self.cfg["telemetry_interval"], "telemetría"), (self._t_maintenance, 30, "mantenimiento")):
            self.tasks.append(loop.create_task(self._loop(fn, iv, nm)))

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        if self.tshark:
            self.tshark.stop()
        self.stop_sniffer()
        try:
            if self.recording_since is not None:
                await asyncio.to_thread(self.save_recording)
            await asyncio.to_thread(self.write_report)
        except Exception:
            log.exception("No se pudo escribir el informe final")
