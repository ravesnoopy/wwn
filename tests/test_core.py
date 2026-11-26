import json
import os
import stat

import pytest

from whitewidow_net import config, detection, oui, profiles, scanner


def test_config_creates_tokens_with_0600(env):
    cfg = config.load()
    assert len(cfg["admin_token"]) >= 32 and cfg["admin_token"] != cfg["viewer_token"]
    assert stat.S_IMODE(os.stat(config.config_path()).st_mode) == 0o600
    assert config.load()["admin_token"] == cfg["admin_token"]  # persistente


def test_config_masks_secrets(env):
    cfg = config.load()
    cfg["integrations"]["adguard"]["password"] = "x"
    m = config.masked(cfg)
    assert m["admin_token"] == "********" and m["integrations"]["adguard"]["password"] == "********"


def test_default_is_passive_and_local(env):
    cfg = config.load()
    assert cfg["host"] == "127.0.0.1" and cfg["control_enabled"] is False and cfg["control_dry_run"] is True


def test_oui_random_mac_and_builtin():
    assert oui.is_random("da:a1:19:00:00:01") and not oui.is_random("b8:27:eb:00:00:01")
    assert oui.vendor("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert "aleatoria" in oui.vendor("da:a1:19:00:00:01")


def test_scan_refuses_public_and_large_ranges():
    with pytest.raises(scanner.ScanRefused):
        scanner.validate_target("8.8.8.0/24")
    with pytest.raises(scanner.ScanRefused):
        scanner.validate_target("10.0.0.0/8")
    assert str(scanner.validate_target("192.168.1.0/24")) == "192.168.1.0/24"


def test_scan_finds_local_listener():
    import asyncio

    async def go():
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.2", 0)
        port = srv.sockets[0].getsockname()[1]
        found = await scanner._tcp("127.0.0.2", port, asyncio.Semaphore(1))
        closed = await scanner._tcp("127.0.0.3", 9, asyncio.Semaphore(1))
        srv.close()
        return found, closed
    found, closed = asyncio.run(go())
    assert found == "open" and closed == "refused"  # 'refused' = host vivo


def test_active_scan_of_loopback_range():
    res = scanner.scan("127.0.0.0/30", port_scan=False, active=True)
    assert {"127.0.0.1", "127.0.0.2"} <= {r["ip"] for r in res}


def test_classify_is_estimated_not_certain():
    assert scanner.classify("m", "", "", [9100], False, False)[0] == "Impresora"
    assert scanner.classify("m", "", "", [], True, False)[0] == "Router / gateway"
    assert scanner.classify("m", "", "", [], False, False)[0] == "Desconocido"


SIG = {"interface": "wlan0", "ip": "192.168.1.20", "gateway": "192.168.1.1", "gateway_mac": "aa:bb:cc:00:00:01",
       "subnet": "192.168.1.0/24", "ssid": "CasaWifi", "dns": ["192.168.1.1"]}


def test_profile_created_then_recognized_despite_ip_change(db):
    n1, new1, _ = profiles.identify(db, SIG)
    assert new1
    moved = dict(SIG, ip="192.168.1.77", ssid="")  # otra IP y sin SSID
    n2, new2, score = profiles.identify(db, moved)
    assert not new2 and n2["id"] == n1["id"] and score >= 5


def test_same_subnet_different_gateway_is_new_network(db):
    n1, _, _ = profiles.identify(db, SIG)
    other = dict(SIG, gateway_mac="11:22:33:44:55:66", ssid="OficinaWifi", dns=["8.8.8.8"])
    n2, new2, _ = profiles.identify(db, other)
    assert new2 and n2["id"] != n1["id"]  # 192.168.1.0/24 repetida no confunde redes


def test_gateway_mac_change_raises_alert(db):
    profiles.identify(db, SIG)
    profiles.identify(db, dict(SIG, gateway_mac="de:ad:be:ef:00:01"))
    assert db.one("SELECT 1 FROM alerts WHERE rule='GATEWAY_MAC_CHANGED'")


def test_beacon_detection_regular_vs_irregular():
    reg = [1000 + i * 60 for i in range(12)]
    mean, sd, cv = detection.beacon_stats(reg)
    assert cv < 0.01 and mean == 60
    irr = [0, 5, 90, 100, 400, 410, 900, 1500, 1510, 2400]
    assert detection.beacon_stats(irr)[2] > 0.5
    assert detection.beacon_stats([1, 2, 3]) is None


def test_beacon_alert_created(db):
    import time
    now = int(time.time())
    for i in range(12):
        db.execute("INSERT INTO conn_sessions(dest,port,ts) VALUES('203.0.113.9',443,?)", (now - 3600 + i * 120,))
    detection.check_beaconing(db, "203.0.113.9", 443)
    a = db.one("SELECT * FROM alerts WHERE rule='BEACONING_PATTERN'")
    assert a and json.loads(a["evidence"])["sesiones"] == 12 and a["status"] == "open"
    detection.check_beaconing(db, "203.0.113.9", 443)  # deduplicada
    assert db.one("SELECT COUNT(*) c FROM alerts")["c"] == 1


def test_domain_checks(db):
    assert detection.check_domain(db, "xkq93jfhs02ndkw8dj3ks9.com")
    assert detection.check_domain(db, "malo.tk")
    assert detection.check_domain(db, "wikipedia.org") is None
    db.execute("INSERT INTO blocklist VALUES('bad.example.com',1)")
    assert detection.check_domain(db, "bad.example.com") == "en lista de bloqueo"


def test_db_persistence(env):
    from whitewidow_net.db import DB
    d = DB(env / "p.db")
    d.audit("x", "y")
    d.close()
    d2 = DB(env / "p.db")
    assert d2.one("SELECT COUNT(*) c FROM audit")["c"] == 1
    d2.close()


def test_retention_purge(db):
    db.execute("INSERT INTO traffic VALUES(1,'e',0,0,0,0)")
    db.purge(30)
    assert db.one("SELECT COUNT(*) c FROM traffic")["c"] == 0


def test_recognition_without_gateway_mac(db):
    sig = {"interface": "eth0", "ip": "10.0.0.5", "gateway": "10.0.0.1", "gateway_mac": "", "subnet": "10.0.0.0/24", "ssid": "Oficina", "dns": []}
    n1, _, _ = profiles.identify(db, sig)
    n2, new2, _ = profiles.identify(db, dict(sig, ip="10.0.0.9"))
    assert not new2 and n2["id"] == n1["id"]
    n3, new3, _ = profiles.identify(db, dict(sig, gateway="10.0.0.254", ssid="Otra"))
    assert new3  # misma subred pero distinta gateway/SSID: otra red
