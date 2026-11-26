"""Telemetría del endpoint local: conexiones, procesos con actividad de red y tráfico de la interfaz.
Privilegios mínimos: solo se registran procesos con conexiones de red; no se lee contenido ni argumentos."""
import json
import time

import psutil

from . import detection, services

KNOWN_APPS = {"firefox": "Firefox", "chrome": "Google Chrome", "chromium": "Chromium", "brave": "Brave", "spotify": "Spotify",
              "steam": "Steam", "discord": "Discord", "telegram": "Telegram", "slack": "Slack", "zoom": "Zoom", "teams": "Microsoft Teams",
              "thunderbird": "Thunderbird", "ssh": "OpenSSH", "sshd": "OpenSSH Server", "curl": "curl", "wget": "wget", "apt": "APT",
              "dropbox": "Dropbox", "signal-desktop": "Signal", "code": "VS Code", "python3": "Python", "docker-proxy": "Docker"}
PORT_SERVICES = {22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 123: "NTP", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
                 993: "IMAPS", 1883: "MQTT", 3389: "RDP", 5222: "XMPP", 5228: "Google Push", 8080: "HTTP-alt"}
SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")


VISIT_GAP = 1800  # 30 min: separa una visita de otra (retención)


class Telemetry:
    def __init__(self, db):
        self.db = db
        self._prev = None
        self.proc_cache = {}
        self._watch_cache, self._custom_cache, self._watch_ts = {k: "alertar" for k in services.DEFAULT_WATCH}, [], 0.0

    def _refresh_policy(self):
        """Política por servicio y reglas propias. Las publica el monitor en la base de datos (sniffer_state) para el proceso de escucha."""
        now = time.time()
        if now - self._watch_ts > 30:
            self._watch_ts = now
            try:
                st = self.db.get_state()
                if st.get("service_actions"):
                    self._watch_cache = {k: a for k, a in json.loads(st["service_actions"]).items() if a in ("alertar", "bloquear")}
                elif st.get("watch_services"):
                    self._watch_cache = {k: "alertar" for k in json.loads(st["watch_services"]) if k in services.SERVICES}
                self._custom_cache = [c for c in json.loads(st.get("custom_services") or "[]") if c.get("key") and c.get("pattern")]
            except (ValueError, TypeError, AttributeError):
                pass

    def _watch(self):
        self._refresh_policy()
        return self._watch_cache

    def _custom(self):
        self._refresh_policy()
        return self._custom_cache

    def record_visit(self, device_id, domain, custom=()):
        """Visitas sin repeticiones: consultas del mismo dispositivo al mismo dominio/app dentro de 30 min son UNA visita;
        pasados 30 min es una visita nueva (retención: el dispositivo volvió)."""
        if services.is_infra(domain):
            return
        key, label, kind = services.group_for(domain, custom)
        now = int(time.time())
        last = self.db.one("SELECT id,ts_last,nth FROM domain_visits WHERE gkey=? AND device_id=? ORDER BY ts_last DESC LIMIT 1", (key, device_id))
        if last and now - last["ts_last"] < VISIT_GAP:
            self.db.execute("UPDATE domain_visits SET ts_last=?, hits=hits+1 WHERE id=?", (now, last["id"]))
        else:
            self.db.execute("INSERT INTO domain_visits(device_id,gkey,glabel,gkind,domain,ts_start,ts_last,hits,nth) VALUES(?,?,?,?,?,?,?,1,?)",
                            (device_id, key, label, kind, domain, now, now, (last["nth"] + 1) if last else 1))

    def _proc(self, pid, now):
        if pid is None:
            return None
        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.Error, OSError):
                exe = ""
            try:
                user = p.username()
            except (psutil.Error, KeyError, OSError):
                user = ""
            try:
                parent = (p.parent().name() if p.parent() else "") or ""
            except (psutil.Error, OSError):
                parent = ""
        except (psutil.Error, OSError):
            return None
        reason = ""
        if exe.startswith(SUSPICIOUS_DIRS):
            reason = f"ejecutable en directorio temporal ({exe}) - indicio, no confirmación"
        elif exe.endswith(" (deleted)"):
            reason = "ejecutable eliminado del disco mientras sigue en ejecución - indicio, no confirmación"
        row = self.db.one("SELECT id FROM processes WHERE name=? AND exe=?", (name, exe))
        if row:
            self.db.execute("UPDATE processes SET last_seen=?,username=?,parent=COALESCE(NULLIF(?,''),parent) WHERE id=?", (now, user, parent, row["id"]))
        else:
            self.db.execute("INSERT INTO processes(name,exe,username,first_seen,last_seen,suspicious,reason,parent) VALUES(?,?,?,?,?,?,?,?)",
                            (name, exe, user, now, now, 1 if reason else 0, reason, parent))
        if reason:
            detection.raise_alert(self.db, "SUSPICIOUS_PROCESS", "medium", f"Proceso con actividad de red: {name}", reason,
                                  {"pid": pid, "nombre": name, "ruta": exe}, dedupe_key=f"proc:{name}:{exe}", window=86400)
        return name

    def collect_connections(self, network_id=None, device_id=None):
        now = int(time.time())
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return []
        listening = {c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN and c.laddr}
        snapshot = []
        for c in conns:
            if not c.laddr:
                continue
            raddr = c.raddr.ip if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            if raddr.startswith("127.") or raddr == "::1" or (c.laddr.ip.startswith("127.") and not raddr):
                continue
            proto = "tcp" if c.type == 1 else "udp"
            if c.status == psutil.CONN_LISTEN:
                direction = "listen"
            elif c.laddr.port in listening:
                direction = "inbound"
            else:
                direction = "outbound"
            item = {"proto": proto, "laddr": c.laddr.ip, "lport": c.laddr.port, "raddr": raddr, "rport": rport,
                    "status": c.status, "direction": direction, "pid": c.pid}
            snapshot.append(item)
            key = f"{proto}|{c.laddr.ip}|{c.laddr.port}|{raddr}|{rport}|{c.pid}"
            name = self._proc(c.pid, now)
            ex = self.db.one("SELECT id FROM connections WHERE ckey=?", (key,))
            if ex:
                self.db.execute("UPDATE connections SET ts_last=?,count=count+1,status=?,process=COALESCE(?,process) WHERE id=?",
                                (now, c.status, name, ex["id"]))
            else:
                self.db.execute("INSERT INTO connections(ckey,network_id,device_id,ts_first,ts_last,proto,laddr,lport,raddr,rport,status,direction,pid,process) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (key, network_id, device_id, now, now, proto, c.laddr.ip, c.laddr.port, raddr, rport, c.status, direction, c.pid, name))
                if direction == "outbound" and raddr and not _is_private(raddr):
                    self.db.execute("INSERT INTO conn_sessions(dest,port,ts) VALUES(?,?,?)", (raddr, rport, now))
                    detection.check_beaconing(self.db, raddr, rport, network_id, device_id)
            if name:
                self.db.execute("UPDATE processes SET conn_count=conn_count+1 WHERE name=? AND last_seen=?", (name, now))
        detection.check_portscan_inbound(self.db, snapshot, set(), network_id)
        return snapshot

    def sample_traffic(self, iface, network_id=None):
        now = time.time()
        try:
            io = psutil.net_io_counters(pernic=True).get(iface)
        except OSError:
            io = None
        if not io:
            return None
        rx_rate = tx_rate = 0.0
        if self._prev and self._prev[0] == iface and now > self._prev[1]:
            dt = now - self._prev[1]
            rx_rate = max(0, io.bytes_recv - self._prev[2]) / dt
            tx_rate = max(0, io.bytes_sent - self._prev[3]) / dt
            detection.check_traffic_spike(self.db, tx_rate, network_id)
        self._prev = (iface, now, io.bytes_recv, io.bytes_sent)
        self.db.execute("INSERT INTO traffic(ts,interface,rx_bytes,tx_bytes,rx_rate,tx_rate) VALUES(?,?,?,?,?,?)",
                        (int(now), iface, io.bytes_recv, io.bytes_sent, rx_rate, tx_rate))
        return {"rx_rate": rx_rate, "tx_rate": tx_rate}

    def ingest_domain(self, domain, device_id=0, source="dns"):
        d = domain.lower().rstrip(".")
        if not d or len(d) > 253:
            return
        now = int(time.time())
        reason = detection.check_domain(self.db, d)
        custom = self._custom()
        svc = services.classify_domain(d, custom)
        if reason:
            cat = "sospechoso (estimado)"
        elif svc:
            cat = f"{svc['category']}: {svc['label']}"
        else:
            cat = "sin clasificar"
        row = self.db.one("SELECT id FROM domains WHERE domain=? AND device_id=?", (d, device_id))
        if row:
            self.db.execute("UPDATE domains SET count=count+1,last_seen=?,category=? WHERE id=?", (now, cat, row["id"]))
        else:
            self.db.execute("INSERT INTO domains(domain,device_id,first_seen,last_seen,category,source) VALUES(?,?,?,?,?,?)",
                            (d, device_id, now, now, cat, source))
        if reason:
            detection.raise_alert(self.db, "SUSPICIOUS_DOMAIN", "low", f"Dominio sospechoso: {d}", f"Clasificación estimada: {reason}.",
                                  {"dominio": d, "motivo": reason, "fuente": source}, device_id=device_id or None, dedupe_key=f"dom:{d}", window=86400)
        self.record_visit(device_id, d, custom)
        action = self._watch().get(svc["key"]) if svc and svc["strong"] else None
        if action:
            self._alert_watched(svc, d, device_id, source, action)

    def _alert_watched(self, svc, domain, device_id, source, action="alertar"):
        dev = self.db.one("SELECT ip,hostname,label,vendor,dtype FROM devices WHERE id=?", (device_id,)) if device_id else None
        who = (dev.get("label") or dev.get("hostname") or dev.get("ip")) if dev else "un dispositivo no identificado"
        adult = svc["key"] == "adulto"
        detection.raise_alert(
            self.db, "WATCHED_SERVICE", "high" if action == "bloquear" else "medium" if adult else "low",
            f"{svc['label']}: actividad de {who}" + (" (configurado como BLOQUEAR)" if action == "bloquear" else ""),
            f"Se observó una consulta o conexión hacia {domain}. Indica acceso a ese servicio desde el dispositivo; no muestra qué contenido vio. "
            "Si el dispositivo no es el de esta computadora, solo se ve cuando la interfaz recibe ese tráfico (ver Actividad).",
            {"servicio": svc["label"], "dominio": domain, "fuente": source, "politica": action, "ip": dev.get("ip") if dev else None,
             "nombre": dev.get("hostname") if dev else None}, device_id=device_id or None,
            dedupe_key=f"watch:{svc['key']}:{device_id}", window=1800)


def _is_private(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return True
