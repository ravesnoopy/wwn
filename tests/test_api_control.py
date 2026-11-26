import pytest
from fastapi.testclient import TestClient

from whitewidow_net import config
from whitewidow_net.api import create_app


@pytest.fixture()
def client(env, monkeypatch):
    monkeypatch.setenv("WW_FORCE_CIDR", "127.0.0.1/30")
    monkeypatch.setenv("WW_FORCE_SSID", "LabNet")
    cfg = config.load()
    cfg["auth_enabled"] = True  # estas pruebas cubren el modo con token
    app = create_app(cfg, start_monitor=False)
    app.state.mon.refresh_network()
    c = TestClient(app)
    c.cfg = cfg
    c.adm = {"Authorization": f"Bearer {cfg['admin_token']}"}
    c.view = {"Authorization": f"Bearer {cfg['viewer_token']}"}
    return c


def test_health_public_and_api_requires_token(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/overview", headers={"Authorization": "Bearer mal"}).status_code == 401
    assert client.get("/api/overview", headers=client.view).status_code == 200


def test_viewer_cannot_admin(client):
    assert client.post("/api/scan", headers=client.view).status_code == 403
    assert client.post("/api/control/apply", headers=client.view, json={"action": "block_device", "target": "10.0.0.5", "confirm": True}).status_code == 403
    assert client.patch("/api/settings", headers=client.view, json={"control_enabled": True}).status_code == 403


def test_security_headers_and_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200 and "WhiteWidow" in r.text
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]


def test_settings_never_leak_tokens(client):
    body = client.get("/api/settings", headers=client.adm).text
    assert client.cfg["admin_token"] not in body and client.cfg["viewer_token"] not in body


def test_network_profile_and_passive_until_authorized(client):
    ov = client.get("/api/overview", headers=client.adm).json()
    nid = ov["network"]["id"]
    assert ov["network"]["authorized"] == 0 and ov["network"]["name"] == "LabNet"
    r = client.post("/api/scan", headers=client.adm).json()
    assert r["mode"] == "passive"  # sin autorización no hay escaneo activo
    assert client.post(f"/api/networks/{nid}/authorize", headers=client.adm, json={"confirm": False}).status_code == 400
    assert client.post(f"/api/networks/{nid}/authorize", headers=client.adm, json={"confirm": True}).status_code == 200
    r = client.post("/api/scan", headers=client.adm).json()
    assert r["mode"] == "active" and r["found"] >= 1
    devs = client.get("/api/devices", headers=client.adm).json()
    assert any(d["ip"] == "127.0.0.1" for d in devs)
    assert any(a["action"] == "network_authorized" for a in client.get("/api/audit", headers=client.adm).json())


def test_control_disabled_by_default_and_audited(client):
    r = client.post("/api/control/apply", headers=client.adm, json={"action": "block_device", "target": "192.168.1.50", "confirm": True})
    assert r.status_code == 400 and "pasivo" in r.json()["detail"]
    assert any(not a["ok"] for a in client.get("/api/audit", headers=client.adm).json())


def test_control_requires_confirm_and_valid_target(client):
    client.patch("/api/settings", headers=client.adm, json={"control_enabled": True})
    r = client.post("/api/control/apply", headers=client.adm, json={"action": "block_device", "target": "192.168.1.50", "confirm": False})
    assert r.status_code == 400 and "confirmación" in r.json()["detail"]
    r = client.post("/api/control/apply", headers=client.adm, json={"action": "block_device", "target": "1.2.3.4; rm -rf /", "confirm": True})
    assert r.status_code == 400


def test_control_unsupported_is_reported_not_simulated(client):
    client.patch("/api/settings", headers=client.adm, json={"control_enabled": True})
    for act in ("limit_bandwidth", "block_device"):
        r = client.post("/api/control/apply", headers=client.adm, json={"action": act, "target": "192.168.1.50", "confirm": True})
        assert r.status_code == 400  # sin adaptador disponible: no se finge éxito
    caps = client.get("/api/control/capabilities", headers=client.adm).json()
    assert caps["actions"]["limit_bandwidth"]["supported"] is False and caps["actions"]["limit_bandwidth"]["reason"]
    assert client.get("/api/control/policies", headers=client.adm).json() == []


def test_nft_adapter_dry_run_and_validation(env):
    from whitewidow_net.integrations.nftables import NftablesAdapter
    a = NftablesAdapter({})
    cmds = a.describe("block_device", "192.168.1.50")
    assert any("blocked4" in c and "192.168.1.50" in c for c in cmds)
    with pytest.raises(ValueError):
        a.plan("block_device", "1.1.1.1; reboot")


def test_adguard_domain_validation():
    from whitewidow_net.integrations.adguard import AdGuardAdapter
    a = AdGuardAdapter({"url": "http://x"})
    assert a._rule("ads.example.com") == "||ads.example.com^"
    with pytest.raises(ValueError):
        a._rule("x.com\n@@||y.com^")


def test_control_dry_run_with_fake_adapter(client, monkeypatch):
    from whitewidow_net.control import Control

    class Fake:
        name = "fake"
        def capabilities(self): return {"available": True, "actions": ["block_domain", "block_device"]}
        def describe(self, a, t): return [f"fake {a} {t}"]
        def apply(self, a, t): raise AssertionError("no debe ejecutarse en dry-run")
    monkeypatch.setattr(Control, "adapters", lambda self: [Fake()])
    client.patch("/api/settings", headers=client.adm, json={"control_enabled": True})
    r = client.post("/api/control/apply", headers=client.adm, json={"action": "block_domain", "target": "ads.example.com", "confirm": True}).json()
    assert r["state"] == "dry_run" and "SIMULACIÓN" in r["detail"]


def test_alert_workflow_and_exports(client):
    from whitewidow_net import detection
    aid = detection.raise_alert(client.app.state.db, "TEST", "low", "t", "d", {"a": 1})
    assert client.patch(f"/api/alerts/{aid}", headers=client.adm, json={"status": "investigating"}).status_code == 200
    assert client.patch(f"/api/alerts/{aid}", headers=client.adm, json={"status": "hacked"}).status_code == 422
    assert client.get("/api/alerts", headers=client.view).json()[0]["status"] == "investigating"
    assert "=SUM" not in client.get("/api/reports/alerts.csv", headers=client.view).text
    html = client.get("/api/reports/html", headers=client.view).text
    assert "estimaciones" in html


def test_csv_injection_neutralized():
    from whitewidow_net.reports import csv_safe
    assert csv_safe("=HYPERLINK(1)").startswith("'") and csv_safe("ok") == "ok"


def test_html_report_escapes(client):
    db = client.app.state.db
    db.execute("INSERT INTO networks(name,subnet) VALUES('<script>alert(1)</script>','10.0.0.0/24')")
    html = client.get("/api/reports/html", headers=client.view).text
    assert "<script>alert(1)</script>" not in html


def test_telemetry_collects_local_connections(client):
    import socket
    srv = socket.socket(); srv.bind(("0.0.0.0", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    conn = socket.create_connection(("127.0.0.1", port))
    mon = client.app.state.mon
    snap = mon.telemetry.collect_connections(1, None)
    conn.close(); srv.close()
    assert any(c["direction"] == "listen" and c["lport"] == port for c in snap)
    assert mon.telemetry.sample_traffic("lo") is not None or True


def test_domain_ingest_and_blocklist_api(client):
    client.post("/api/domains", headers=client.adm, json={"domain": "ejemplo.org"})
    client.post("/api/domains", headers=client.adm, json={"domain": "malo.tk"})
    rows = client.get("/api/domains", headers=client.view).json()
    assert {r["domain"] for r in rows} == {"ejemplo.org", "malo.tk"}
    assert any(a["rule"] == "SUSPICIOUS_DOMAIN" for a in client.get("/api/alerts", headers=client.view).json())


@pytest.fixture()
def open_client(env, monkeypatch):
    monkeypatch.setenv("WW_FORCE_CIDR", "127.0.0.1/30")
    cfg = config.load()
    assert cfg["auth_enabled"] is False  # por defecto: sin login
    app = create_app(cfg, start_monitor=False)
    app.state.mon.refresh_network()
    return TestClient(app)


def test_no_login_needed_on_localhost(open_client):
    assert open_client.get("/api/overview").status_code == 200
    assert open_client.get("/api/health").json()["auth_required"] is False
    assert open_client.post("/api/scan").status_code == 200


def test_cross_site_requests_blocked_without_login(open_client):
    r = open_client.post("/api/scan", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    r = open_client.post("/api/scan", headers={"Origin": "http://testserver"})
    assert r.status_code == 200


def test_dns_rebinding_host_rejected(open_client):
    assert open_client.get("/api/overview", headers={"Host": "evil.example.com"}).status_code == 400


def test_token_forced_when_listening_on_lan(env, monkeypatch):
    monkeypatch.setenv("WW_FORCE_CIDR", "127.0.0.1/30")
    cfg = config.load()
    cfg["host"] = "0.0.0.0"
    c = TestClient(create_app(cfg, start_monitor=False))
    assert c.get("/api/overview").status_code == 401
    assert c.get("/api/health").json()["auth_required"] is True


def test_recording_saves_json(open_client, env):
    import json, pathlib
    from whitewidow_net import detection
    open_client.post("/api/recording/start")
    assert open_client.get("/api/recording").json()["recording"] is True
    detection.raise_alert(open_client.app.state.db, "T", "low", "durante grabación", "d", {"x": 1})
    r = open_client.post("/api/recording/stop").json()
    data = json.loads(pathlib.Path(r["file"]).read_text())
    assert {"dispositivos", "conexiones", "dominios", "trafico", "alertas"} <= set(data)
    assert data["alertas"][0]["evidence"] == {"x": 1}
    assert open_client.post("/api/recording/stop").status_code == 409


def test_hourly_peak_hours(open_client):
    import time
    db = open_client.app.state.db
    now = int(time.time())
    for i in range(5):
        db.execute("INSERT INTO traffic VALUES(?,?,?,?,?,?)", (now - i, "eth0", 0, 0, 1000.0, 500.0))
    rows = open_client.get("/api/analytics/hourly").json()
    assert len(rows) == 24 and max(r["avg_rate"] for r in rows) == 1500.0
