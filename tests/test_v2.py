"""Pruebas v2: visitas sin repeticiones (30 min), agrupación, nombres de dispositivo y reglas propias del firewall."""
import json

from whitewidow_net import fingerprint, services
from whitewidow_net.telemetry import Telemetry, VISIT_GAP


def add_device(db, ip="192.168.1.50", **kw):
    cols = {"network_id": 1, "mac": "02:cc:00:00:00:09", "ip": ip, "hostname": "", "online": 1, "first_seen": 1, "last_seen": 1}
    cols.update(kw)
    return db.execute(f"INSERT INTO devices({','.join(cols)}) VALUES({','.join('?' * len(cols))})", tuple(cols.values()))


def test_visits_collapse_within_30_minutes_and_count_return_after(db):
    did = add_device(db)
    t = Telemetry(db)
    for d in ("www.youtube.com", "rr1.googlevideo.com", "youtubei.googleapis.com"):   # misma app, misma visita
        t.ingest_domain(d, did)
    v = db.query("SELECT * FROM domain_visits")
    assert len(v) == 1 and v[0]["gkey"] == "youtube" and v[0]["hits"] == 3 and v[0]["nth"] == 1
    db.execute("UPDATE domain_visits SET ts_start=ts_start-?, ts_last=ts_last-?", (VISIT_GAP + 60, VISIT_GAP + 60))
    t.ingest_domain("www.youtube.com", did)                                           # pasaron más de 30 min: visita nueva (retención)
    v = db.query("SELECT nth FROM domain_visits ORDER BY ts_start")
    assert [r["nth"] for r in v] == [1, 2]


def test_visits_are_per_device_and_skip_infrastructure(db):
    a, b = add_device(db), add_device(db, ip="192.168.1.51", mac="02:cc:00:00:00:0a")
    t = Telemetry(db)
    t.ingest_domain("www.netflix.com", a)
    t.ingest_domain("www.netflix.com", b)
    t.ingest_domain("1.1.168.192.in-addr.arpa", a)
    t.ingest_domain("time.ntp.org", a)
    t.ingest_domain("api.sitio.com.mx", a)
    t.ingest_domain("cdn.sitio.com.mx", a)                                              # mismo dominio registrable: una sola visita
    rows = db.query("SELECT gkey, device_id FROM domain_visits ORDER BY id")
    assert sorted((r["gkey"], r["device_id"]) for r in rows) == sorted([("netflix", a), ("netflix", b), ("sitio.com.mx", a)])


def test_grouping_helpers():
    assert services.e2ld("a.b.ejemplo.com") == "ejemplo.com" and services.e2ld("www.tienda.com.mx") == "tienda.com.mx" and services.e2ld("ejemplo.org") == "ejemplo.org"
    assert services.is_infra("4.3.2.1.in-addr.arpa") and services.is_infra("impresora.local") and services.is_infra("_dns-sd._udp.lan")
    assert not services.is_infra("www.youtube.com")
    assert services.group_for("rr1.googlevideo.com") == ("youtube", "YouTube", "app")
    assert services.group_for("img.sitio.com.mx") == ("sitio.com.mx", "sitio.com.mx", "dominio")


def test_custom_rule_matches_domain_and_subdomains_only():
    custom = [{"key": "c_mi-sitio-com", "label": "Mi sitio", "pattern": "mi-sitio.com"}]
    assert services.classify_domain("mi-sitio.com", custom)["label"] == "Mi sitio"
    assert services.classify_domain("cdn.app.mi-sitio.com", custom)["key"] == "c_mi-sitio-com"
    assert services.classify_domain("otro-mi-sitio.com", custom) is None


def test_custom_rule_triggers_policy_alert_and_policy_is_read_from_state(db):
    did = add_device(db, hostname="SalaTV")
    db.set_state("custom_services", json.dumps([{"key": "c_x", "label": "Sitio X", "pattern": "sitio-x.com"}]))
    db.set_state("service_actions", json.dumps({"c_x": "bloquear", "netflix": "alertar"}))
    t = Telemetry(db)
    t.ingest_domain("www.sitio-x.com", did)
    t.ingest_domain("www.youtube.com", did)                                             # sin política: no alerta
    a = db.query("SELECT severity,title FROM alerts WHERE rule='WATCHED_SERVICE'")
    assert len(a) == 1 and a[0]["severity"] == "high" and "BLOQUEAR" in a[0]["title"] and "SalaTV" in a[0]["title"]


def dev(**kw):
    base = {"mac": "3c:95:09:2c:b9:8d", "ip": "192.168.0.178", "hostname": "", "vendor": "", "services": "[]", "ports": "[]", "random_mac": 0, "is_self": 0, "is_gateway": 0}
    base.update(kw)
    return base


def test_display_name_is_never_empty():
    assert fingerprint.display_name(dev(label="Tele de Ana")) == "Tele de Ana"
    assert fingerprint.display_name(dev(hostname="iPhone-de-Leo.local")) == "iPhone-de-Leo"
    n = fingerprint.display_name(dev(vendor="Samsung Electronics Co.,Ltd", services='["_googlecast._tcp"]'))
    assert n.startswith("Samsung") and "TV" in n and n.endswith("B98D")
    n2 = fingerprint.display_name(dev(mac="82:68:60:0f:30:a4", vendor="MAC aleatoria/administrada localmente", random_mac=1))
    assert n2 and "Teléfono" in n2 and n2.endswith("30A4")
    assert fingerprint.display_name(dev(hostname="a1b2c3d4e5f6a7b8")) != "a1b2c3d4e5f6a7b8"      # nombre genérico/UUID: se reemplaza
    assert "gateway" in fingerprint.display_name(dev(is_gateway=1, vendor="Hitron Technologies"))
    assert fingerprint.display_name(dev(is_self=1, hostname="mi-pc")) == "Este equipo (mi-pc)"


def test_detected_as_never_says_unknown_and_camelcase_tv_name():
    for d in (dev(), dev(random_mac=1), dev(vendor="Acme"), dev(vendor="Espressif Inc."), dev(services='["_ipp._tcp"]'), dev(hostname="SalaTV")):
        t = fingerprint.detected_as(d)
        assert t and "desconocid" not in t.lower()
    assert fingerprint.category(dev(hostname="SalaTV"))["category"] == "TV"
    assert fingerprint.detected_as(dev(services='["_googlecast._tcp"]')).startswith("Chromecast")
    assert fingerprint.category(dev(hostname="Switch-1A2B", vendor="Nintendo Co.,Ltd"))["category"] == "Consola"
    assert fingerprint.category(dev(hostname="Echo-Dot-3"))["category"] == "Bocina / asistente"
