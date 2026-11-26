"""Escucha PASIVA de la red (AF_PACKET). No envía ningún paquete.

Funciona con cualquier modem/router porque solo oye lo que llega a esta interfaz:
  - ARP, DHCP, mDNS, SSDP y NetBIOS: los dispositivos se anuncian solos (nombre, MAC, servicios, SO estimado).
  - Escaneos dirigidos a este equipo (barridos ARP, sondeos SYN) e intentos de conexión fallidos.
  - Si la interfaz ve tráfico ajeno (gateway, puerto espejo): consultas DNS y SNI de TLS por dispositivo.
Corre como proceso aparte con el permiso mínimo cap_net_raw (ver scripts/enable-sniffer.sh); el servidor web no tiene ese permiso.

Solo en redes que el operador marcó como AUTORIZADAS (y con probe_discovery activo) hace además un sondeo de descubrimiento:
solicitudes ARP a la subred y una consulta mDNS y otra SSDP estándar, para que TODOS los dispositivos se anuncien y se
identifiquen (nombre, servicios, tipo). No intercepta ni redirige tráfico de nadie."""
import ipaddress
import json
import logging
import os
import signal
import socket
import struct
import sys
import time
from collections import defaultdict, deque

from . import config, detection, inventory, scanner
from .db import DB
from .telemetry import Telemetry

log = logging.getLogger("whitewidow.sniffer")
EXIT_NO_PERMISSION = 3
SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC = 263, 1, 1


def mac_s(b):
    return ":".join(f"{x:02x}" for x in b)


# ------------------------------------------------------------------ parsers
def parse_frame(d):
    """Ethernet(+VLAN) -> dict con ARP o IPv4 (TCP/UDP/ICMP). None si no interesa."""
    if len(d) < 14:
        return None
    et = struct.unpack("!H", d[12:14])[0]
    off = 14
    if et == 0x8100 and len(d) >= 18:
        et, off = struct.unpack("!H", d[16:18])[0], 18
    f = {"eth_dst": mac_s(d[0:6]), "eth_src": mac_s(d[6:12]), "t": None}
    if et == 0x0806 and len(d) >= off + 28:
        op = struct.unpack("!H", d[off + 6:off + 8])[0]
        f.update(t="arp", op=op, smac=mac_s(d[off + 8:off + 14]), sip=socket.inet_ntoa(d[off + 14:off + 18]),
                 tmac=mac_s(d[off + 18:off + 24]), tip=socket.inet_ntoa(d[off + 24:off + 28]))
        return f
    if et != 0x0800 or len(d) < off + 20:
        return None
    ihl = (d[off] & 0x0F) * 4
    if ihl < 20 or len(d) < off + ihl:
        return None
    if struct.unpack("!H", d[off + 6:off + 8])[0] & 0x1FFF:  # fragmento no inicial
        return None
    proto = d[off + 9]
    f.update(ip_src=socket.inet_ntoa(d[off + 12:off + 16]), ip_dst=socket.inet_ntoa(d[off + 16:off + 20]), proto=proto)
    p = d[off + ihl:]
    if proto == 17 and len(p) >= 8:
        f.update(t="udp", sport=struct.unpack("!H", p[0:2])[0], dport=struct.unpack("!H", p[2:4])[0], payload=p[8:])
    elif proto == 6 and len(p) >= 20:
        doff = (p[12] >> 4) * 4
        f.update(t="tcp", sport=struct.unpack("!H", p[0:2])[0], dport=struct.unpack("!H", p[2:4])[0], flags=p[13], payload=p[doff:] if doff >= 20 else b"")
    elif proto == 1 and len(p) >= 1:
        f.update(t="icmp", icmp_type=p[0])
    else:
        return None
    return f


def parse_name(d, off):
    labels, jumped, end, hops = [], False, off, 0
    while off < len(d) and hops < 60:
        n = d[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(d):
                raise ValueError("puntero truncado")
            ptr = ((n & 0x3F) << 8) | d[off + 1]
            if not jumped:
                end = off + 2
            off, jumped, hops = ptr, True, hops + 1
            continue
        labels.append(d[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    if not jumped:
        end = off
    return ".".join(labels), end


def parse_dns(d):
    """Devuelve {'qr','questions':[(nombre,tipo)],'answers':[(nombre,tipo,dato)]} o None."""
    try:
        if len(d) < 12:
            return None
        _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", d[:12])
        off, qs, ans = 12, [], []
        for _ in range(min(qd, 20)):
            name, off = parse_name(d, off)
            qs.append((name, struct.unpack("!H", d[off:off + 2])[0]))
            off += 4
        for _ in range(min(an + ns + ar, 60)):
            name, off = parse_name(d, off)
            typ, _, _, rdl = struct.unpack("!HHIH", d[off:off + 10])
            off += 10
            rd = d[off:off + rdl]
            val = ""
            if typ == 1 and rdl == 4:
                val = socket.inet_ntoa(rd)
            elif typ == 12:
                val = parse_name(d, off)[0]
            elif typ == 33 and rdl > 6:
                val = parse_name(d, off + 6)[0]
            ans.append((name, typ, val))
            off += rdl
        return {"qr": bool(flags & 0x8000), "opcode": (flags >> 11) & 0xF, "questions": qs, "answers": ans}
    except (struct.error, ValueError, IndexError):
        return None


def parse_dhcp(p):
    if len(p) < 241 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    o = {"op": p[0], "ciaddr": socket.inet_ntoa(p[12:16]), "yiaddr": socket.inet_ntoa(p[16:20]),
         "mac": mac_s(p[28:34]), "opts": {}}
    i = 240
    while i < len(p) and p[i] != 255:
        if p[i] == 0:
            i += 1
            continue
        if i + 1 >= len(p):
            break
        c, n = p[i], p[i + 1]
        o["opts"][c] = p[i + 2:i + 2 + n]
        i += 2 + n
    t = o["opts"].get(53)
    o["type"] = t[0] if t else 0
    return o


def parse_nbns_name(p):
    """Nombre NetBIOS del emisor en registros/respuestas (no en simples consultas)."""
    if len(p) < 47:
        return None
    flags = struct.unpack("!H", p[2:4])[0]
    if not (flags & 0x8000 or ((flags >> 11) & 0xF) in (5, 8, 9)):
        return None
    if p[12] != 0x20:
        return None
    enc = p[13:45]
    try:
        raw = bytes(((enc[i] - 65) << 4) | (enc[i + 1] - 65) for i in range(0, 32, 2))
    except (IndexError, ValueError):
        return None
    if raw[15] not in (0x00, 0x20):
        return None
    name = raw[:15].decode("ascii", "ignore").strip()
    return name or None


def parse_sni(p):
    """Nombre de servidor (SNI) de un TLS ClientHello contenido en un único segmento."""
    try:
        if len(p) < 48 or p[0] != 0x16 or p[5] != 1:
            return None
        i = 43
        i += 1 + p[i]
        i += 2 + struct.unpack("!H", p[i:i + 2])[0]
        i += 1 + p[i]
        end = i + 2 + struct.unpack("!H", p[i:i + 2])[0]
        i += 2
        while i + 4 <= min(end, len(p)):
            t, n = struct.unpack("!HH", p[i:i + 4])
            if t == 0:
                nl = struct.unpack("!H", p[i + 7:i + 9])[0]
                name = p[i + 9:i + 9 + nl].decode("ascii")
                return name if "." in name else None
            i += 4 + n
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


def parse_ssdp(p):
    try:
        lines = p.decode("latin-1").split("\r\n")
    except UnicodeDecodeError:
        return None
    first = lines[0].upper()
    if not (first.startswith("NOTIFY") or first.startswith("HTTP/1.1 200")):
        return None
    h = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            h[k.strip().upper()] = v.strip()
    return h


# ------------------------------------------------------------------ sondeo de descubrimiento (solo redes autorizadas)
MDNS_QUERY_NAMES = ("_services._dns-sd._udp.local", "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
                    "_androidtvremote2._tcp.local", "_companion-link._tcp.local", "_apple-mobdev2._tcp.local", "_hap._tcp.local",
                    "_homekit._tcp.local", "_ipp._tcp.local", "_printer._tcp.local", "_smb._tcp.local", "_workstation._tcp.local",
                    "_spotify-connect._tcp.local", "_amzn-wplay._tcp.local", "_matter._tcp.local", "_hue._tcp.local")
SSDP_MSEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
PROBE_GAP = 3.0  # segundos hasta la segunda pasada ARP (equipos WiFi en ahorro de energía)


def build_arp_request(src_mac, src_ip, dst_ip):
    """Trama Ethernet con 'who-has dst_ip' (ARP op 1) en difusión."""
    sm = bytes.fromhex(src_mac.replace(":", ""))
    frame = (b"\xff" * 6 + sm + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sm + socket.inet_aton(src_ip)
             + b"\x00" * 6 + socket.inet_aton(dst_ip))
    return frame.ljust(60, b"\x00")


def build_mdns_query(names, qid=0x5757):
    """Consulta mDNS PTR. Con puerto de origen distinto de 5353 los equipos responden por unicast directamente a este equipo."""
    out = struct.pack("!HHHHHH", qid, 0, len(names), 0, 0, 0)
    for n in names:
        for label in n.split("."):
            b = label.encode("ascii")
            out += bytes([len(b)]) + b
        out += b"\x00" + struct.pack("!HH", 12, 1)
    return out


# ------------------------------------------------------------------ motor
class Sniffer:
    def __init__(self, db):
        self.db = db
        self.tel = Telemetry(db)
        self.st = {}
        self.counters = defaultdict(int)
        self.ip2mac, self.last_seen = {}, {}
        self.syn_hist, self.rst_hist = defaultdict(deque), defaultdict(deque)
        self.arp_hist = defaultdict(deque)
        self.dhcp_servers = {}
        self.pending = {}
        self.dev_cache = {}
        self.last_probe, self.last_probe_req, self.second_pass_at, self.udp_probe = 0.0, 0.0, 0.0, None
        self.reload_state()

    def reload_state(self):
        self.st = self.db.get_state()
        try:
            self.subnet = ipaddress.ip_network(self.st.get("subnet") or "0.0.0.0/32", strict=False)
        except ValueError:
            self.subnet = ipaddress.ip_network("0.0.0.0/32")

    @property
    def nid(self):
        try:
            return int(self.st.get("network_id") or 0) or None
        except ValueError:
            return None

    def _in_subnet(self, ip):
        try:
            return ipaddress.ip_address(ip) in self.subnet
        except ValueError:
            return False

    # ---- salida
    def event(self, kind, src_ip="", src_mac="", dst_ip="", dst_port=0, detail="", n=1):
        now = int(time.time())
        key = f"{kind}|{src_ip}|{dst_ip}|{dst_port}|{now // 60}"
        self.db.execute("INSERT INTO net_events(ekey,ts,ts_last,kind,src_ip,src_mac,dst_ip,dst_port,count,detail,network_id) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(ekey) DO UPDATE SET count=count+?, ts_last=excluded.ts_last",
                        (key, now, now, kind, src_ip, src_mac, dst_ip, dst_port, n, detail[:500], self.nid, n))

    def observe(self, mac, ip, hostname="", services=(), dvendor="", dfp="", force=False):
        now = time.time()
        k = (mac, ip)
        if not force and not hostname and not services and not dvendor and now - self.last_seen.get(k, 0) < 30:
            return
        self.last_seen[k] = now
        if ip:
            self.ip2mac[ip] = mac
        inventory.observe(self.db, self.nid, mac, ip, hostname, services, dvendor, dfp, self.st.get("gateway_ip", ""), self.st.get("self_ip", ""))

    def _device_id(self, ip):
        c = self.dev_cache.get(ip)
        if c and time.time() - c[1] < 60:
            return c[0]
        r = self.db.one("SELECT id FROM devices WHERE network_id=? AND ip=?", (self.nid, ip)) if self.nid else None
        self.dev_cache[ip] = (r["id"] if r else 0, time.time())
        return self.dev_cache[ip][0]

    # ---- entrada
    def handle_frame(self, data, now=None):
        now = now or time.time()
        f = parse_frame(data)
        self.counters["frames"] += 1
        if f is None:
            return
        self_mac, self_ip = self.st.get("self_mac", ""), self.st.get("self_ip", "")
        d0 = int(f["eth_dst"][:2], 16)
        if not (d0 & 1) and f["eth_dst"] != self_mac and f["eth_src"] != self_mac:
            self.counters["foreign_unicast"] += 1  # tráfico entre otros: la interfaz tiene visibilidad extra
        t = f["t"]
        if t == "arp":
            self.counters["arp"] += 1
            return self.on_arp(f, now)
        if f["eth_src"] != self_mac and self._in_subnet(f["ip_src"]):
            self.observe(f["eth_src"], f["ip_src"])
        if t == "udp":
            dp, sp, pl = f["dport"], f["sport"], f["payload"]
            if {sp, dp} & {67, 68}:
                self.on_dhcp(f, pl)
            elif dp == 5353 or sp == 5353:
                self.on_mdns(f, pl)
            elif dp == 1900 or sp == 1900:
                self.on_ssdp(f, pl)
            elif dp == 137 or sp == 137:
                self.on_nbns(f, pl)
            elif dp == 53:
                self.on_dns_query(f, pl)
            elif sp == 53:
                self.on_dns_response(f, pl)
        elif t == "tcp":
            self.on_tcp(f, now)
        elif t == "icmp" and f["icmp_type"] == 8 and f["ip_dst"] == self_ip and f["ip_src"] != self_ip:
            self.event("icmp_echo", f["ip_src"], f["eth_src"], self_ip, 0, "ping recibido")

    def on_arp(self, f, now):
        self_mac, gw = self.st.get("self_mac", ""), self.st.get("gateway_ip", "")
        sip, smac = f["sip"], f["smac"]
        if sip != "0.0.0.0" and self._in_subnet(sip):
            old = self.ip2mac.get(sip)
            if old and old != smac and smac != self_mac:
                sev = "high" if sip == gw else "medium"
                detection.raise_alert(self.db, "ARP_CONFLICT", sev, f"La IP {sip} cambió de MAC ({old} → {smac})",
                                      "Dos MAC distintas anuncian la misma IP. Puede ser un cambio legítimo de equipo/DHCP o una suplantación ARP" + (" DEL GATEWAY." if sip == gw else "."),
                                      {"ip": sip, "mac_anterior": old, "mac_nueva": smac, "es_gateway": sip == gw}, network_id=self.nid,
                                      dedupe_key=f"arpc:{sip}:{smac}", window=3600)
                self.event("arp_conflict", sip, smac, "", 0, f"antes {old}")
            self.observe(smac, sip)
        if f["op"] == 1 and smac != self_mac and f["tip"] != sip:  # barrido ARP: muchas IP distintas consultadas
            h = self.arp_hist[smac]
            h.append((now, f["tip"]))
            while h and now - h[0][0] > 10:
                h.popleft()
            targets = {t for _, t in h}
            if len(targets) >= 20:
                aid = detection.raise_alert(self.db, "ARP_SWEEP", "medium", f"Barrido de red (ARP) desde {sip} / {smac}",
                                            "Un equipo consultó 20 o más IP distintas en 10 s: típico de un escáner de red (nmap, Fing, etc.). Algunos routers también lo hacen al arrancar.",
                                            {"origen_mac": smac, "origen_ip": sip, "ips_consultadas": len(targets)}, network_id=self.nid,
                                            dedupe_key=f"sweep:{smac}", window=1800)
                if aid:
                    self.event("arp_sweep", sip, smac, "", 0, f"{len(targets)} IP en 10 s")
                h.clear()

    def on_dhcp(self, f, pl):
        m = parse_dhcp(pl)
        if not m:
            return
        self.counters["dhcp"] += 1
        o = m["opts"]
        if m["op"] == 1:  # cliente
            host = o.get(12, b"").decode("utf-8", "ignore").strip("\x00 ")
            vc = o.get(60, b"").decode("utf-8", "ignore")
            fp = ",".join(str(x) for x in o.get(55, b""))
            ip = socket.inet_ntoa(o[50]) if len(o.get(50, b"")) == 4 else (m["ciaddr"] if m["ciaddr"] != "0.0.0.0" else "")
            if host or vc or fp:
                self.observe(m["mac"], ip, host, (), vc, fp, force=True)
        elif m["op"] == 2:  # servidor
            if m["type"] == 6:
                self.event("dhcp_nak", f["ip_src"], f["eth_src"], "", 0, "El servidor DHCP rechazó una solicitud")
            sid = socket.inet_ntoa(o[54]) if len(o.get(54, b"")) == 4 else f["ip_src"]
            self.dhcp_servers[f["eth_src"]] = sid
            if len(self.dhcp_servers) > 1:
                detection.raise_alert(self.db, "MULTIPLE_DHCP_SERVERS", "medium", "Más de un servidor DHCP en la red",
                                      "Se observaron respuestas DHCP de varios equipos. Puede ser un segundo router/repetidor mal configurado o un servidor DHCP no autorizado.",
                                      {"servidores": self.dhcp_servers}, network_id=self.nid, dedupe_key="dhcp2", window=86400)
            if m["yiaddr"] != "0.0.0.0" and m["mac"]:
                self.observe(m["mac"], m["yiaddr"], force=True)

    def on_mdns(self, f, pl):
        d = parse_dns(pl)
        if not d or not d["qr"]:
            return
        self.counters["mdns"] += 1
        host, svcs = "", set()
        for name, typ, val in d["answers"]:
            if typ == 1 and name.endswith(".local") and (val == f["ip_src"]):
                host = name[:-6]
            if typ in (12, 33):
                src = val if name == "_services._dns-sd._udp.local" else name
                parts = [x for x in src.split(".") if x]
                for i, x in enumerate(parts):
                    if x.startswith("_") and i + 1 < len(parts) and parts[i + 1].startswith("_"):
                        svcs.add(f"{x}.{parts[i + 1]}")
                        break
        if (host or svcs) and self._in_subnet(f["ip_src"]):
            self.observe(f["eth_src"], f["ip_src"], host, sorted(svcs), force=True)

    def on_ssdp(self, f, pl):
        h = parse_ssdp(pl)
        if not h:
            return
        self.counters["ssdp"] += 1
        svcs = []
        for key in ("NT", "ST"):
            v = h.get(key, "")
            parts = v.split(":")
            if v and parts[0] != "uuid":
                svcs.append("upnp:" + (parts[-2] if parts[0] == "urn" and len(parts) >= 4 else parts[-1]))
        if h.get("SERVER"):
            svcs.append("server:" + h["SERVER"][:70])
        if svcs and self._in_subnet(f["ip_src"]):
            self.observe(f["eth_src"], f["ip_src"], "", svcs, force=True)

    def on_nbns(self, f, pl):
        n = parse_nbns_name(pl)
        if n and self._in_subnet(f["ip_src"]):
            self.counters["nbns"] += 1
            self.observe(f["eth_src"], f["ip_src"], n.lower(), ["netbios"], force=True)

    def on_dns_query(self, f, pl):
        d = parse_dns(pl)
        if d and not d["qr"] and d["questions"] and self._in_subnet(f["ip_src"]):
            self.counters["dns_queries"] += 1
            for name, typ in d["questions"][:3]:
                if typ in (1, 28, 65) and "." in name:
                    self.tel.ingest_domain(name, self._device_id(f["ip_src"]), "pasivo-dns")

    def on_dns_response(self, f, pl):
        """Respuestas DNS dirigidas a un equipo de la subred: asocia IP -> nombre para traducir las conexiones a servicios."""
        d = parse_dns(pl)
        if not d or not d["qr"] or not d["questions"] or not self._in_subnet(f["ip_dst"]):
            return
        qname = d["questions"][0][0].lower().rstrip(".")
        if "." not in qname:
            return
        ips = [val for _, typ, val in d["answers"] if typ == 1 and val][:10]
        if not ips:
            return
        self.counters["dns_responses"] += 1
        now = int(time.time())
        for ip in ips:
            self.db.execute("INSERT INTO ip_names(ip,domain,ts) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET domain=excluded.domain, ts=excluded.ts", (ip, qname, now))

    def on_tcp(self, f, now):
        fl, self_ip, src, dst = f["flags"], self.st.get("self_ip", ""), f["ip_src"], f["ip_dst"]
        if f["dport"] == 443 and f["payload"][:1] == b"\x16" and self._in_subnet(src):
            sni = parse_sni(f["payload"])
            if sni:
                self.counters["sni"] += 1
                self.tel.ingest_domain(sni, self._device_id(src), "pasivo-sni")
        if not self_ip:
            return
        if src == self_ip and fl & 0x04 and dst != self_ip and self._in_subnet(dst):
            # Nuestro RST = alguien intentó conectar a un puerto cerrado de este equipo
            self.counters["failed_attempts"] += 1
            self.rst_hist[dst].append(now)
            self.event("tcp_probe_failed", dst, "", self_ip, f["sport"], "conexión a puerto cerrado (respondimos RST)")
        elif dst == self_ip and fl & 0x02 and not fl & 0x10 and src != self_ip:
            self.counters["syn_to_self"] += 1
            h = self.syn_hist[src]
            h.append((now, f["dport"]))
            while h and now - h[0][0] > 30:
                h.popleft()
            ports = {p for _, p in h}
            if len(ports) >= 10:
                failed = sum(1 for t in self.rst_hist[src] if now - t <= 30)
                aid = detection.raise_alert(self.db, "PORT_SCAN_INBOUND", "high", f"Escaneo de puertos hacia este equipo desde {src}",
                                            "Un mismo origen envió SYN a 10 o más puertos distintos en 30 s.",
                                            {"origen_ip": src, "origen_mac": f["eth_src"], "puertos_distintos": len(ports), "puertos_ejemplo": sorted(ports)[:30], "intentos_fallidos": failed},
                                            network_id=self.nid, dedupe_key=f"pscan:{src}", window=1800)
                if aid:
                    self.event("port_scan", src, f["eth_src"], self_ip, 0, f"{len(ports)} puertos en 30 s, {failed} cerrados")
                h.clear()
        elif fl & 0x04 and src != self_ip and self._in_subnet(src):
            self.counters["resets_seen"] += 1  # solo visible si la interfaz ve tráfico ajeno
            self.event("tcp_reset_seen", src, f["eth_src"], dst, f["sport"],
                       "Un equipo rechazó una conexión de este equipo (RST)" if dst == self_ip else "RST observado entre otros equipos (conexión rechazada o cortada)")

    # ---- sondeo de descubrimiento
    def probe_allowed(self):
        """Solo con probe_discovery activo, red AUTORIZADA, rango privado y tamaño razonable."""
        if self.st.get("probe_enabled", "1") != "1" or not (self.nid and self.st.get("self_mac") and self.st.get("self_ip")):
            return False
        row = self.db.one("SELECT authorized FROM networks WHERE id=?", (self.nid,))
        if not row or not row["authorized"]:
            return False
        try:
            scanner.validate_target(str(self.subnet), 1024)
        except scanner.ScanRefused:
            return False
        return True

    def _send_arp(self, sock):
        me_mac, me_ip = self.st["self_mac"], self.st["self_ip"]
        sent = 0
        for i, h in enumerate(self.subnet.hosts()):
            ip = str(h)
            if ip == me_ip:
                continue
            try:
                sock.send(build_arp_request(me_mac, me_ip, ip))
            except OSError:
                break
            sent += 1
            if sent % 32 == 0:
                time.sleep(0.01)  # no saturar la tarjeta WiFi
        self.counters["probe_arp"] += sent
        return sent

    def _send_udp_probes(self, me_ip):
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            u.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me_ip))
            u.bind((me_ip, 0))
            u.sendto(build_mdns_query(MDNS_QUERY_NAMES), ("224.0.0.251", 5353))
            u.sendto(SSDP_MSEARCH, ("239.255.255.250", 1900))
            self.udp_probe = (u, time.time() + 8)  # se mantiene abierto unos segundos para recibir las respuestas
            self.counters["probe_udp"] += 1
        except OSError:
            self.counters["probe_udp_errors"] += 1

    def maybe_probe(self, sock, now=None):
        """Lanza el sondeo si toca (intervalo o petición manual) y la red está autorizada. Devuelve True si envió algo."""
        now = now or time.time()
        if self.second_pass_at and now >= self.second_pass_at:
            self.second_pass_at = 0.0
            if self.probe_allowed():
                self._send_arp(sock)
                return True
        try:
            req = float(self.st.get("probe_request") or 0)
            interval = max(60, int(float(self.st.get("probe_interval") or 300)))
        except ValueError:
            req, interval = 0.0, 300
        if not (req > self.last_probe_req or now - self.last_probe >= interval) or not self.probe_allowed():
            return False
        self.last_probe_req, self.last_probe = max(self.last_probe_req, req), now
        if self._send_arp(sock) == 0:
            return False
        self._send_udp_probes(self.st["self_ip"])
        self.second_pass_at = now + PROBE_GAP
        return True

    # ---- ciclo de vida
    def flush(self):
        self.db.set_state("counters", json.dumps(dict(self.counters)))
        self.db.set_state("heartbeat", int(time.time()))
        for k in [k for k, v in self.last_seen.items() if time.time() - v > 600]:
            del self.last_seen[k]
        if self.udp_probe and time.time() > self.udp_probe[1]:
            self.udp_probe[0].close()
            self.udp_probe = None


def open_socket(iface, promisc=False):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((iface, 0))
    if promisc:
        s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, struct.pack("iHH8s", socket.if_nametoindex(iface), PACKET_MR_PROMISC, 0, b""))
    s.settimeout(1.0)
    return s


def run(db, stop=lambda: False, max_seconds=None):
    sn = Sniffer(db)
    sock, cur = None, None
    t0 = last = time.time()
    db.set_state("pid", os.getpid())
    try:
        while not stop() and (max_seconds is None or time.time() - t0 < max_seconds):
            if time.time() - last >= 5 or sock is None:
                last = time.time()
                sn.reload_state()
                want = (sn.st.get("iface", ""), sn.st.get("want_promisc") == "1")
                if want != cur:
                    if sock:
                        sock.close()
                        sock = None
                    cur = want
                    if want[0]:
                        try:
                            sock = open_socket(*want)
                            db.set_state("status", "running")
                            db.set_state("status_detail", f"escuchando en {want[0]}" + (" (promiscuo)" if want[1] else ""))
                        except PermissionError:
                            db.set_state("status", "no_permission")
                            db.set_state("status_detail", "Falta el permiso cap_net_raw. Ejecuta ./scripts/enable-sniffer.sh")
                            return EXIT_NO_PERMISSION
                        except OSError as e:
                            db.set_state("status", "error")
                            db.set_state("status_detail", f"No se pudo abrir {want[0]}: {e}")
                    else:
                        db.set_state("status", "waiting")
                        db.set_state("status_detail", "Sin red conectada")
                sn.flush()
                if sock is not None:
                    try:
                        sn.maybe_probe(sock)
                    except Exception:  # el sondeo es opcional: nunca debe detener la escucha
                        log.debug("error en sondeo", exc_info=True)
            if sock is None:
                time.sleep(1)
                continue
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                sock, cur = None, None
                continue
            try:
                sn.handle_frame(data)
            except Exception:  # un paquete raro no debe detener la escucha
                sn.counters["parse_errors"] += 1
                log.debug("error de parseo", exc_info=True)
    finally:
        sn.flush()
        if db.get_state().get("status") not in ("no_permission", "error"):  # conserva el motivo de la salida
            db.set_state("status", "stopped")
        if sock:
            sock.close()
    return 0


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db = DB(config.data_dir() / "whitewidow.db")
    stop = {"v": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(v=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(v=True))
    return run(db, lambda: stop["v"])


if __name__ == "__main__":
    sys.exit(main())
