"""Pruebas de v1.2: servicios vigilados, categorías de dispositivo, resumen de tráfico en bytes y sondeo de descubrimiento."""
import json
import socket
import struct
import time

import pytest

from whitewidow_net import fingerprint, profiles, services, sniffer, usage
from whitewidow_net.sniffer import Sniffer
from whitewidow_net.telemetry import Telemetry

ME_MAC, ME_IP, GW_MAC, GW_IP = "02:aa:00:00:00:01", "192.168.1.20", "02:bb:00:00:00:01", "192.168.1.1"


def mb(m): return bytes.fromhex(m.replace(":", ""))
def ib(i): return socket.inet_aton(i)
def eth(dst, src, et, p): return mb(dst) + mb(src) + struct.pack("!H", et) + p
def ipv4(src, dst, proto, p): return struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(p), 0, 0, 64, proto, 0) + ib(src) + ib(dst) + p
def udp(sp, dp, p): return struct.pack("!HHHH", sp, dp, 8 + len(p), 0) + p
def frame_udp(smac, sip, dmac, dip, sp, dp, p): return eth(dmac, smac, 0x0800, ipv4(sip, dip, 17, udp(sp, dp, p)))
def dns_name(n): return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"


def dns_msg(flags, qs=(), ans=()):
    out = struct.pack("!HHHHHH", 0, flags, len(qs), len(ans), 0, 0)
    for n, t in qs:
        out += dns_name(n) + struct.pack("!HH", t, 1)
    for n, t, rd in ans:
        out += dns_name(n) + struct.pack("!HHIH", t, 1, 120, len(rd)) + rd
    return out


def add_device(db, ip="192.168.1.50", host="", **kw):
    cols = {"network_id": 1, "mac": "02:cc:00:00:00:09", "ip": ip, "hostname": host, "online": 1, "first_seen": 1, "last_seen": 1}
    cols.update(kw)
    return db.execute(f"INSERT INTO devices({','.join(cols)}) VALUES({','.join('?' * len(cols))})", tuple(cols.values()))


# ---------------------------------------------------------------- servicios
def test_catalog_classifies_services_and_ignores_unknown():
    assert services.classify_domain("rr3---sn-abc.googlevideo.com")["key"] == "youtube"
    assert services.classify_domain("WWW.YouTube.com.")["strong"] is True
    assert services.classify_domain("occ-0-1.nflxvideo.net")["key"] == "netflix"
    assert services.classify_domain("www.pornhub.com")["category"] == "Adultos"
    assert services.classify_domain("algo.xxx")["key"] == "adulto"          # TLD de adultos
    assert services.classify_domain("i.ytimg.com")["strong"] is False        # CDN compartido: se clasifica, no alerta
    assert services.classify_domain("notyoutube.com") is None                # no basta con terminar igual
    assert services.classify_domain("ejemplo.org") is None
    assert services.classify_domain("localhost") is None


def test_noise_filter_hides_local_chatter_keeps_real_destinations():
    base = {"direction": "outbound", "rport": 443, "raddr": "142.250.1.1"}
    assert not services.is_noise(base)
    assert services.is_noise({**base, "direction": "listen"})
    assert services.is_noise({**base, "raddr": ""})
    assert services.is_noise({**base, "raddr": "192.168.1.255", "rport": 137})
    assert services.is_noise({**base, "raddr": "224.0.0.251", "rport": 5353})
    assert services.is_noise({**base, "raddr": "239.255.255.250", "rport": 1900})
    assert services.is_noise({**base, "raddr": "162.159.200.1", "rport": 123})   # NTP
    assert services.is_noise({**base, "raddr": "192.168.1.1", "rport": 53})      # DNS al router
    assert not services.is_noise({**base, "proto": "udp"})                       # QUIC a un destino público se conserva


def test_watched_service_alert_once_and_adult_is_medium(db):
    did = add_device(db, host="TeleSala")
    t = Telemetry(db)
    t.ingest_domain("www.youtube.com", did, "pasivo-dns")
    t.ingest_domain("rr1.googlevideo.com", did, "pasivo-sni")   # mismo servicio y dispositivo: sin alerta duplicada
    t.ingest_domain("i.ytimg.com", did)                         # débil: sin alerta
    t.ingest_domain("open.spotify.com", did)                    # no vigilado por defecto
    t.ingest_domain("www.pornhub.com", did)
    t.ingest_domain("www.netflix.com", 0)                       # dispositivo desconocido: también se avisa
    rows = db.query("SELECT * FROM alerts WHERE rule='WATCHED_SERVICE' ORDER BY id")
    assert [r["severity"] for r in rows] == ["low", "medium", "low"]
    assert "TeleSala" in rows[0]["title"] and "YouTube" in rows[0]["title"]
    assert "no identificado" in rows[2]["title"]
    cats = {r["domain"]: r["category"] for r in db.query("SELECT domain,category FROM domains")}
    assert cats["www.youtube.com"] == "Video: YouTube" and cats["open.spotify.com"] == "Música: Spotify" and cats["www.pornhub.com"] == "Adultos: Sitio para adultos"


def test_watch_list_comes_from_state(db):
    did = add_device(db)
    db.set_state("watch_services", json.dumps(["adulto"]))
    t = Telemetry(db)
    t.ingest_domain("www.youtube.com", did)
    t.ingest_domain("www.netflix.com", did)
    assert db.one("SELECT COUNT(*) c FROM alerts WHERE rule='WATCHED_SERVICE'")["c"] == 0
    t.ingest_domain("xvideos.com", did)
    assert db.one("SELECT COUNT(*) c FROM alerts WHERE rule='WATCHED_SERVICE'")["c"] == 1
    db.set_state("watch_services", "[]")
    t2 = Telemetry(db)
    t2.ingest_domain("hbomax.com", did)
    t2.ingest_domain("pornhub.com", did)
    assert db.one("SELECT COUNT(*) c FROM alerts WHERE rule='WATCHED_SERVICE'")["c"] == 1  # lista vacía: sin avisos nuevos


# ---------------------------------------------------------------- categorías
def cat(**kw):
    base = {"services": "[]", "ports": "[]", "hostname": "", "vendor": "", "os_guess": "", "dtype": "", "random_mac": 0, "is_self": 0, "is_gateway": 0}
    base.update(kw)
    return fingerprint.category(base)


def test_category_examples():
    assert cat(is_gateway=1)["category"] == "Router"
    assert cat(is_self=1)["category"] == "Computadora"
    assert cat(services='["_googlecast._tcp"]')["category"] == "TV"
    assert cat(services='["_androidtvremote2._tcp"]')["category"] == "TV"
    assert cat(services='["_airplay._tcp"]', vendor="Samsung Electronics")["category"] == "TV"
    assert cat(services='["_airplay._tcp"]', vendor="Apple")["category"] != "TV"     # un Mac también anuncia AirPlay
    assert cat(hostname="iPad-de-Ana")["category"] == "Tablet"
    assert cat(hostname="Galaxy-Tab-A8")["category"] == "Tablet"
    assert cat(hostname="iPhone-de-Leo")["category"] == "Teléfono"
    assert cat(hostname="DESKTOP-AB12CD")["category"] == "Computadora"
    assert cat(hostname="LAPTOP-9XYZ")["category"] == "Computadora"
    assert cat(hostname="Sala-TV")["category"] == "TV"
    assert cat(services='["_ipp._tcp"]')["category"] == "Impresora"
    assert cat(os_guess="Android (estimado)")["category"] == "Teléfono o tablet"
    assert cat(os_guess="macOS / iOS (estimado)")["confidence"] == "baja"
    assert cat(hostname="stv1")["category"] != "TV"                                  # "tv" dentro de otra palabra no cuenta


def test_category_private_mac_is_low_confidence_and_manual_wins():
    c = cat(random_mac=1, vendor="MAC aleatoria/administrada localmente")
    assert c["category"] == "Teléfono o tablet" and c["confidence"] == "baja"
    assert cat(vendor="Acme Corp")["category"] == "Sin identificar"
    m = cat(random_mac=1, user_type="Tablet")
    assert m == {"category": "Tablet", "basis": "elegida por ti", "confidence": "manual"}
    assert cat(user_type="inventada")["category"] == "Sin identificar"               # valor no válido: se ignora


# ---------------------------------------------------------------- tráfico en bytes
def test_usage_summary_counts_bytes_handles_reset_and_gap():
    now = 1_800_000_000
    rows, rx, tx = [], 0, 0
    for i in range(0, 600, 5):                       # 10 minutos, 1 KB/s bajada, 0.5 KB/s subida
        rx, tx = rx + 5000, tx + 2500
        rows.append({"ts": now - 3600 + i, "interface": "wlan0", "rx_bytes": rx, "tx_bytes": tx})
    rows.append({"ts": now - 1800, "interface": "wlan0", "rx_bytes": 100, "tx_bytes": 50})   # tras un hueco largo: no se atribuye
    rows.append({"ts": now - 1795, "interface": "wlan0", "rx_bytes": 5100, "tx_bytes": 2550})
    rows.append({"ts": now - 1790, "interface": "wlan0", "rx_bytes": 20, "tx_bytes": 10})    # contador reiniciado: cuenta el valor nuevo
    out = usage.summarize(rows, now)
    assert out["last_24h"]["rx"] == 119 * 5000 + 5000 + 20 and out["last_24h"]["tx"] == 119 * 2500 + 2500 + 10
    assert out["last_hour"]["total"] == out["last_hour"]["rx"] + out["last_hour"]["tx"]
    assert out["since"] == now - 3600 and out["days"] and out["hours"]


def test_usage_ignores_interface_changes_and_empty():
    now = 1_800_000_000
    rows = [{"ts": now - 10, "interface": "wlan0", "rx_bytes": 10, "tx_bytes": 10}, {"ts": now - 5, "interface": "enp7s0", "rx_bytes": 99999, "tx_bytes": 99999}]
    assert usage.summarize(rows, now)["last_hour"]["total"] == 0
    assert usage.summarize([], now)["since"] is None


# ---------------------------------------------------------------- sniffer: DNS, sondeo
@pytest.fixture()
def sn2(db):
    n, _, _ = profiles.identify(db, {"interface": "eth0", "ip": ME_IP, "gateway": GW_IP, "gateway_mac": GW_MAC, "subnet": "192.168.1.0/24", "ssid": "Casa", "dns": []})
    for k, v in (("iface", "eth0"), ("network_id", n["id"]), ("self_ip", ME_IP), ("self_mac", ME_MAC), ("gateway_ip", GW_IP), ("subnet", "192.168.1.0/24")):
        db.set_state(k, v)
    s = Sniffer(db)
    s.net = n
    return s


class FakeSock:
    def __init__(self): self.frames = []
    def send(self, f): self.frames.append(f)


def test_arp_request_frame_roundtrips_through_parser():
    f = sniffer.parse_frame(sniffer.build_arp_request(ME_MAC, ME_IP, "192.168.1.77"))
    assert f["t"] == "arp" and f["op"] == 1 and f["smac"] == ME_MAC and f["sip"] == ME_IP and f["tip"] == "192.168.1.77"
    assert f["eth_dst"] == "ff:ff:ff:ff:ff:ff" and len(sniffer.build_arp_request(ME_MAC, ME_IP, "192.168.1.77")) >= 60


def test_mdns_query_is_valid_dns():
    d = sniffer.parse_dns(sniffer.build_mdns_query(sniffer.MDNS_QUERY_NAMES))
    names = [q[0] for q in d["questions"]]
    assert d["qr"] is False and "_services._dns-sd._udp.local" in names and "_googlecast._tcp.local" in names and len(names) == len(sniffer.MDNS_QUERY_NAMES)


def test_dns_response_maps_ip_to_name(sn2, db):
    msg = dns_msg(0x8180, [("www.youtube.com", 1)], [("www.youtube.com", 1, ib("142.250.80.46")), ("www.youtube.com", 1, ib("142.250.80.47"))])
    sn2.handle_frame(frame_udp(GW_MAC, GW_IP, ME_MAC, ME_IP, 53, 40000, msg))
    rows = {r["ip"]: r["domain"] for r in db.query("SELECT * FROM ip_names")}
    assert rows == {"142.250.80.46": "www.youtube.com", "142.250.80.47": "www.youtube.com"}
    sn2.handle_frame(frame_udp(GW_MAC, GW_IP, ME_MAC, ME_IP, 53, 40000, dns_msg(0x8180, [("sin-respuesta.org", 1)])))  # sin A: no escribe
    assert db.one("SELECT COUNT(*) c FROM ip_names")["c"] == 2


def test_probe_needs_authorization_then_sweeps_subnet_twice(sn2, db):
    sock = FakeSock()
    assert sn2.maybe_probe(sock) is False and sock.frames == []                    # red no autorizada: nada se envía
    db.execute("UPDATE networks SET authorized=1 WHERE id=?", (sn2.net["id"],))
    assert sn2.maybe_probe(sock, now=time.time()) is True
    assert len(sock.frames) == 253                                                # /24 sin este equipo
    targets = {sniffer.parse_frame(f)["tip"] for f in sock.frames}
    assert ME_IP not in targets and GW_IP in targets and "192.168.1.254" in targets
    assert sn2.maybe_probe(sock, now=time.time() + 1) is False                    # no repite antes de tiempo
    assert sn2.maybe_probe(sock, now=time.time() + sniffer.PROBE_GAP + 1) is True  # segunda pasada para equipos en ahorro de energía
    assert len(sock.frames) == 506
    assert sn2.maybe_probe(sock, now=time.time() + sniffer.PROBE_GAP + 2) is False


def test_probe_manual_request_and_switches(sn2, db):
    db.execute("UPDATE networks SET authorized=1 WHERE id=?", (sn2.net["id"],))
    sock = FakeSock()
    t0 = time.time()
    assert sn2.maybe_probe(sock, now=t0) is True
    sn2.second_pass_at = 0.0
    sn2.reload_state()
    assert sn2.maybe_probe(sock, now=t0 + 5) is False
    db.set_state("probe_request", f"{t0 + 6:.3f}")                                # el botón "Escanear ahora" pide otro sondeo
    sn2.reload_state()
    assert sn2.maybe_probe(sock, now=t0 + 7) is True
    sn2.second_pass_at = 0.0
    db.set_state("probe_enabled", "0")                                             # desactivado en Ajustes
    db.set_state("probe_request", f"{t0 + 100:.3f}")
    sn2.reload_state()
    n = len(sock.frames)
    assert sn2.maybe_probe(sock, now=t0 + 101) is False and len(sock.frames) == n


def test_probe_refuses_public_or_huge_ranges(sn2, db):
    db.execute("UPDATE networks SET authorized=1 WHERE id=?", (sn2.net["id"],))
    for net in ("8.8.8.0/24", "10.0.0.0/16"):
        db.set_state("subnet", net)
        sn2.reload_state()
        sock = FakeSock()
        assert sn2.maybe_probe(sock) is False and sock.frames == []


def test_probe_replies_discover_devices_with_names_and_services(sn2, db):
    """Lo que responde un TV a la consulta mDNS (unicast, puerto 5353) lo identifica sin tocar nada más."""
    ans = [("_googlecast._tcp.local", 12, dns_name("Chromecast-Sala._googlecast._tcp.local")), ("Sala-TV.local", 1, ib("192.168.1.60"))]
    tv_mac = "02:dd:00:00:00:60"
    sn2.handle_frame(frame_udp(tv_mac, "192.168.1.60", ME_MAC, ME_IP, 5353, 51000, dns_msg(0x8400, [], ans)))
    d = db.one("SELECT * FROM devices WHERE mac=?", (tv_mac,))
    assert d["hostname"] == "Sala-TV" and "_googlecast._tcp" in json.loads(d["services"])
    assert fingerprint.category(d)["category"] == "TV"
