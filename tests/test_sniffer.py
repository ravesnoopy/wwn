import json
import socket
import struct
import time

import pytest

from whitewidow_net import inventory, profiles, sniffer
from whitewidow_net.sniffer import Sniffer

ME_MAC, ME_IP, GW_MAC, GW_IP = "02:aa:00:00:00:01", "192.168.1.20", "02:bb:00:00:00:01", "192.168.1.1"
PHONE_MAC, PHONE_IP = "02:cc:00:00:00:09", "192.168.1.50"


def mb(m): return bytes.fromhex(m.replace(":", ""))
def ib(i): return socket.inet_aton(i)
def eth(dst, src, et, p): return mb(dst) + mb(src) + struct.pack("!H", et) + p
def arp(op, smac, sip, tmac, tip): return eth(tmac if op == 2 else "ff:ff:ff:ff:ff:ff", smac, 0x0806, struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mb(smac) + ib(sip) + mb(tmac) + ib(tip))
def ipv4(src, dst, proto, p): return struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(p), 0, 0, 64, proto, 0) + ib(src) + ib(dst) + p
def udp(sp, dp, p): return struct.pack("!HHHH", sp, dp, 8 + len(p), 0) + p
def tcp(sp, dp, fl, p=b""): return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, fl, 65535, 0, 0) + p
def frame_udp(smac, sip, dmac, dip, sp, dp, p): return eth(dmac, smac, 0x0800, ipv4(sip, dip, 17, udp(sp, dp, p)))
def frame_tcp(smac, sip, dmac, dip, sp, dp, fl, p=b""): return eth(dmac, smac, 0x0800, ipv4(sip, dip, 6, tcp(sp, dp, fl, p)))


def dns_name(n): return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"
def dns_msg(flags, qs=(), ans=()):
    out = struct.pack("!HHHHHH", 0, flags, len(qs), len(ans), 0, 0)
    for n, t in qs: out += dns_name(n) + struct.pack("!HH", t, 1)
    for n, t, rd in ans: out += dns_name(n) + struct.pack("!HHIH", t, 1, 120, len(rd)) + rd
    return out


def dhcp_req(mac, host, vendor, params, req_ip):
    b = bytes([1, 1, 6, 0]) + b"\0" * 8 + b"\0" * 16 + mb(mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    o = bytes([53, 1, 3, 12, len(host)]) + host.encode() + bytes([60, len(vendor)]) + vendor.encode() + bytes([55, len(params)]) + bytes(params) + bytes([50, 4]) + ib(req_ip) + b"\xff"
    return b + o


def dhcp_offer(server_ip, mac, yi):
    b = bytes([2, 1, 6, 0]) + b"\0" * 8 + b"\0" * 4 + ib(yi) + b"\0" * 8 + mb(mac) + b"\0" * 10 + b"\0" * 192 + b"\x63\x82\x53\x63"
    return b + bytes([53, 1, 2, 54, 4]) + ib(server_ip) + b"\xff"


def client_hello(sni):
    name = sni.encode()
    ext = struct.pack("!HH", 0, len(name) + 5) + struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\0" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


@pytest.fixture()
def sn(db):
    n, _, _ = profiles.identify(db, {"interface": "eth0", "ip": ME_IP, "gateway": GW_IP, "gateway_mac": GW_MAC, "subnet": "192.168.1.0/24", "ssid": "Casa", "dns": []})
    for k, v in (("iface", "eth0"), ("network_id", n["id"]), ("self_ip", ME_IP), ("self_mac", ME_MAC), ("gateway_ip", GW_IP), ("subnet", "192.168.1.0/24")):
        db.set_state(k, v)
    db.execute("INSERT INTO scans(network_id,ts_start,ts_end,mode,hosts_found) VALUES(?,?,?,?,0)", (n["id"], 1, 1, "passive"))  # línea base hecha
    s = Sniffer(db)
    s.nid_ = n["id"]
    return s


def test_parse_frame_arp_and_udp_and_tcp():
    f = sniffer.parse_frame(arp(1, PHONE_MAC, PHONE_IP, "00:00:00:00:00:00", GW_IP))
    assert f["t"] == "arp" and f["sip"] == PHONE_IP and f["smac"] == PHONE_MAC and f["op"] == 1
    f = sniffer.parse_frame(frame_udp(PHONE_MAC, PHONE_IP, GW_MAC, GW_IP, 5000, 53, b"x"))
    assert f["t"] == "udp" and f["dport"] == 53
    f = sniffer.parse_frame(frame_tcp(PHONE_MAC, PHONE_IP, ME_MAC, ME_IP, 4000, 22, 0x02))
    assert f["t"] == "tcp" and f["flags"] == 2
    assert sniffer.parse_frame(b"\x00" * 5) is None  # basura no rompe nada


def test_garbage_never_crashes(sn):
    import os
    for n in (14, 20, 34, 60, 200):
        for _ in range(50):
            sn.handle_frame(os.urandom(n))


def test_arp_discovers_device(sn, db):
    sn.handle_frame(arp(1, PHONE_MAC, PHONE_IP, "00:00:00:00:00:00", GW_IP))
    d = db.one("SELECT * FROM devices WHERE mac=?", (PHONE_MAC,))
    assert d and d["ip"] == PHONE_IP
    assert db.one("SELECT 1 FROM alerts WHERE rule='NEW_DEVICE'")  # hay línea base: el nuevo genera alerta


def test_dhcp_gives_hostname_vendor_and_os(sn, db):
    sn.handle_frame(frame_udp(PHONE_MAC, "0.0.0.0", "ff:ff:ff:ff:ff:ff", "255.255.255.255", 68, 67,
                              dhcp_req(PHONE_MAC, "Galaxy-S23", "android-dhcp-14", [1, 3, 6, 15], PHONE_IP)))
    d = db.one("SELECT * FROM devices WHERE mac=?", (PHONE_MAC,))
    assert d["hostname"] == "Galaxy-S23" and d["dhcp_vendor"] == "android-dhcp-14" and "Android" in d["os_guess"]
    assert d["ip"] == PHONE_IP


def test_multiple_dhcp_servers_alert(sn, db):
    sn.handle_frame(frame_udp(GW_MAC, GW_IP, "ff:ff:ff:ff:ff:ff", "255.255.255.255", 67, 68, dhcp_offer(GW_IP, PHONE_MAC, PHONE_IP)))
    assert not db.one("SELECT 1 FROM alerts WHERE rule='MULTIPLE_DHCP_SERVERS'")
    sn.handle_frame(frame_udp("02:dd:00:00:00:66", "192.168.1.99", "ff:ff:ff:ff:ff:ff", "255.255.255.255", 67, 68, dhcp_offer("192.168.1.99", PHONE_MAC, PHONE_IP)))
    assert db.one("SELECT 1 FROM alerts WHERE rule='MULTIPLE_DHCP_SERVERS'")


def test_mdns_name_and_service_classify_device(sn, db):
    ans = [("Sala-TV.local", 1, ib("192.168.1.60")), ("_googlecast._tcp.local", 12, dns_name("Sala._googlecast._tcp.local"))]
    sn.handle_frame(frame_udp("02:ee:00:00:00:60", "192.168.1.60", "01:00:5e:00:00:fb", "224.0.0.251", 5353, 5353, dns_msg(0x8400, (), ans)))
    d = db.one("SELECT * FROM devices WHERE ip='192.168.1.60'")
    assert d["hostname"] == "Sala-TV" and "Chromecast" in d["dtype"] and "_googlecast._tcp" in d["services"]


def test_ssdp_router_hint(sn, db):
    msg = b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: Linux UPnP/1.0 MiniUPnPd/2.1\r\n\r\n"
    sn.handle_frame(frame_udp("02:ff:00:00:00:77", "192.168.1.77", "01:00:5e:7f:ff:fa", "239.255.255.250", 1900, 1900, msg))
    d = db.one("SELECT * FROM devices WHERE ip='192.168.1.77'")
    assert d["dtype"] == "Router / gateway" and "MiniUPnPd" in d["services"]


def test_netbios_name(sn, db):
    enc = bytes(c for ch in ("PC-OFICINA".ljust(15) + "\x00") for c in (65 + (ord(ch) >> 4), 65 + (ord(ch) & 15)))
    pkt = struct.pack("!HHHHHH", 1, 0x2910, 1, 0, 0, 1) + b"\x20" + enc + b"\x00" + struct.pack("!HH", 0x20, 1)
    sn.handle_frame(frame_udp("02:12:00:00:00:30", "192.168.1.30", "ff:ff:ff:ff:ff:ff", "192.168.1.255", 137, 137, pkt))
    assert db.one("SELECT hostname FROM devices WHERE ip='192.168.1.30'")["hostname"] == "pc-oficina"


def test_arp_conflict_on_gateway_is_high(sn, db):
    sn.handle_frame(arp(2, GW_MAC, GW_IP, ME_MAC, ME_IP))
    sn.handle_frame(arp(2, "02:de:ad:00:00:01", GW_IP, ME_MAC, ME_IP))
    a = db.one("SELECT * FROM alerts WHERE rule='ARP_CONFLICT'")
    assert a and a["severity"] == "high" and json.loads(a["evidence"])["es_gateway"] is True


def test_arp_sweep_detected(sn, db):
    for i in range(2, 30):
        sn.handle_frame(arp(1, "02:99:00:00:00:99", "192.168.1.99", "00:00:00:00:00:00", f"192.168.1.{i}"), now=time.time())
    a = db.one("SELECT * FROM alerts WHERE rule='ARP_SWEEP'")
    assert a and json.loads(a["evidence"])["origen_mac"] == "02:99:00:00:00:99"
    assert db.one("SELECT 1 FROM net_events WHERE kind='arp_sweep'")


def test_normal_arp_is_not_a_sweep(sn, db):
    for i in range(1, 5):
        sn.handle_frame(arp(1, PHONE_MAC, PHONE_IP, "00:00:00:00:00:00", f"192.168.1.{i}"))
    assert not db.one("SELECT 1 FROM alerts WHERE rule='ARP_SWEEP'")


def test_port_scan_and_failed_attempts(sn, db):
    now = time.time()
    for port in range(20, 35):
        sn.handle_frame(frame_tcp(PHONE_MAC, PHONE_IP, ME_MAC, ME_IP, 40000, port, 0x02), now=now)
        sn.handle_frame(frame_tcp(ME_MAC, ME_IP, PHONE_MAC, PHONE_IP, port, 40000, 0x14), now=now)  # nuestro RST|ACK
    a = db.one("SELECT * FROM alerts WHERE rule='PORT_SCAN_INBOUND'")
    ev = json.loads(a["evidence"])
    assert a["severity"] == "high" and ev["puertos_distintos"] >= 10 and ev["intentos_fallidos"] >= 9
    fails = db.query("SELECT * FROM net_events WHERE kind='tcp_probe_failed'")
    assert fails and sum(f["count"] for f in fails) == 15 and fails[0]["src_ip"] == PHONE_IP


def test_single_connection_is_not_scan(sn, db):
    sn.handle_frame(frame_tcp(PHONE_MAC, PHONE_IP, ME_MAC, ME_IP, 40000, 22, 0x02))
    assert not db.one("SELECT 1 FROM alerts WHERE rule='PORT_SCAN_INBOUND'")


def test_dns_query_and_sni_attributed_to_device_when_visible(sn, db):
    sn.handle_frame(arp(1, PHONE_MAC, PHONE_IP, "00:00:00:00:00:00", GW_IP))
    sn.handle_frame(frame_udp(PHONE_MAC, PHONE_IP, GW_MAC, GW_IP, 5555, 53, dns_msg(0x0100, [("ejemplo.org", 1)])))
    sn.handle_frame(frame_tcp(PHONE_MAC, PHONE_IP, GW_MAC, "93.184.216.34", 5556, 443, 0x18, client_hello("www.wikipedia.org")))
    rows = {r["domain"]: r for r in db.query("SELECT * FROM domains")}
    did = db.one("SELECT id FROM devices WHERE mac=?", (PHONE_MAC,))["id"]
    assert rows["ejemplo.org"]["device_id"] == did and rows["ejemplo.org"]["source"] == "pasivo-dns"
    assert rows["www.wikipedia.org"]["device_id"] == did and rows["www.wikipedia.org"]["source"] == "pasivo-sni"
    assert sn.counters["foreign_unicast"] == 2  # tráfico ajeno visible => la interfaz ve más que lo propio


def test_foreign_traffic_not_seen_means_no_extra_visibility(sn):
    sn.handle_frame(frame_udp(PHONE_MAC, PHONE_IP, ME_MAC, ME_IP, 1, 2, b"x"))
    sn.handle_frame(arp(1, PHONE_MAC, PHONE_IP, "00:00:00:00:00:00", GW_IP))
    assert sn.counters["foreign_unicast"] == 0


def test_sni_parser_rejects_garbage():
    assert sniffer.parse_sni(client_hello("a.example.com")) == "a.example.com"
    assert sniffer.parse_sni(b"\x16\x03\x01" + b"\x00" * 10) is None
    assert sniffer.parse_sni(b"GET / HTTP/1.1") is None


def test_dns_compression_loop_does_not_hang():
    evil = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + b"\0\0\0\0"
    sniffer.parse_dns(evil)  # puntero a sí mismo: debe terminar


def test_reset_seen_and_icmp_events(sn, db):
    sn.handle_frame(frame_tcp(GW_MAC, GW_IP, ME_MAC, ME_IP, 443, 41000, 0x04))
    assert db.one("SELECT 1 FROM net_events WHERE kind='tcp_reset_seen'")
    echo = eth(ME_MAC, PHONE_MAC, 0x0800, ipv4(PHONE_IP, ME_IP, 1, b"\x08\x00\x00\x00\x00\x00\x00\x00"))
    sn.handle_frame(echo)
    assert db.one("SELECT 1 FROM net_events WHERE kind='icmp_echo'")


def test_observe_rejects_invalid_macs(db):
    assert inventory.observe(db, 1, "ff:ff:ff:ff:ff:ff", "1.1.1.1") is None
    assert inventory.observe(db, 1, "01:00:5e:00:00:fb", "224.0.0.251") is None
    assert inventory.observe(db, None, "02:00:00:00:00:01", "1.1.1.1") is None


def test_db_migration_adds_columns(env):
    import sqlite3
    from whitewidow_net.db import DB
    p = env / "old.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE devices(id INTEGER PRIMARY KEY, network_id INTEGER, mac TEXT, ip TEXT)")
    c.commit(); c.close()
    d = DB(p)
    assert {"services", "dhcp_vendor", "dhcp_fp"} <= {r["name"] for r in d.query("PRAGMA table_info(devices)")}
    d.close()


def test_real_packet_socket_end_to_end(env, db):
    """Abre un socket AF_PACKET real en loopback, envía un mDNS real y comprueba que el sniffer lo recibe."""
    try:
        s = sniffer.open_socket("lo")
    except (PermissionError, OSError) as e:
        pytest.skip(f"sin permiso cap_net_raw en este entorno: {e}")
    s.close()
    import threading
    n, _, _ = profiles.identify(db, {"interface": "lo", "ip": "127.0.0.1", "gateway": "", "gateway_mac": "", "subnet": "127.0.0.0/8", "ssid": "", "dns": []})
    for k, v in (("iface", "lo"), ("network_id", n["id"]), ("self_ip", "127.0.0.9"), ("self_mac", "02:00:00:00:00:09"), ("subnet", "127.0.0.0/8")):
        db.set_state(k, v)
    t = threading.Thread(target=lambda: sniffer.run(db, max_seconds=4))
    t.start()
    time.sleep(1.5)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = dns_msg(0x8400, (), [("Prueba-Real.local", 1, ib("127.0.0.1"))])
    for _ in range(3):
        tx.sendto(msg, ("127.0.0.1", 5353))
        time.sleep(0.2)
    t.join()
    st = db.get_state()
    assert json.loads(st["counters"]).get("mdns", 0) >= 1


def test_no_permission_status_is_preserved(db, monkeypatch):
    db.set_state("iface", "lo")
    def deny(*a, **k): raise PermissionError("sin cap_net_raw")
    monkeypatch.setattr(sniffer, "open_socket", deny)
    assert sniffer.run(db, max_seconds=3) == sniffer.EXIT_NO_PERMISSION
    st = db.get_state()
    assert st["status"] == "no_permission" and "enable-sniffer.sh" in st["status_detail"]
