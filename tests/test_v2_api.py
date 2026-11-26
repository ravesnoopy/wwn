"""Endpoints v2 (requieren FastAPI): resumen, grupos de dominios/apps, firewall."""
import time

import pytest
from fastapi.testclient import TestClient

from whitewidow_net import config
from whitewidow_net.api import create_app
from whitewidow_net.telemetry import Telemetry


@pytest.fixture()
def client(env, monkeypatch):
    monkeypatch.setenv("WW_FORCE_CIDR", "127.0.0.1/30")
    monkeypatch.setenv("WW_FORCE_SSID", "LabNet")
    cfg = config.load()
    cfg["auth_enabled"] = True
    app = create_app(cfg, start_monitor=False)
    app.state.mon.refresh_network()
    c = TestClient(app)
    c.app_ = app
    c.adm = {"Authorization": f"Bearer {cfg['admin_token']}"}
    c.view = {"Authorization": f"Bearer {cfg['viewer_token']}"}
    return c


def add_device(client, ip="127.0.0.2", host="SalaTV"):
    db, nid = client.app_.state.db, client.app_.state.mon.network["id"]
    return db.execute("INSERT INTO devices(network_id,mac,ip,hostname,online,first_seen,last_seen,services,ports) VALUES(?,?,?,?,?,?,?,?,?)",
                      (nid, "02:cc:00:00:00:09", ip, host, 1, 1, 1, "[]", "[]"))


def test_dashboard_groups_and_feed_use_visits_per_device(client):
    did = add_device(client)
    t = Telemetry(client.app_.state.db)
    t.ingest_domain("www.youtube.com", did)
    t.ingest_domain("rr1.googlevideo.com", did)
    d = client.get("/api/dashboard", headers=client.view).json()
    assert d["devices"]["total"] >= 1 and d["firewall"]["hits"] == 1 and "YouTube" in d["firewall"]["services"]
    g = client.get("/api/groups", headers=client.view).json()
    yt = next(x for x in g if x["key"] == "youtube")
    assert yt["visits"] == 1 and yt["devices"][0]["name"] == "SalaTV" and len(yt["devices"][0]["visits"]) == 1
    assert any(f["event"] == "Inicio en dominio" and f["name"] == "SalaTV" for f in client.get("/api/feed", headers=client.view).json())


def test_firewall_actions_need_admin_and_never_fake_blocking(client):
    assert client.put("/api/firewall/youtube", headers=client.view, json={"action": "bloquear"}).status_code == 403
    r = client.put("/api/firewall/youtube", headers=client.adm, json={"action": "bloquear"}).json()
    assert r["ok"] and r["enforced"] is False and r["detail"]                   # sin adaptador activo: se explica, no se finge
    items = {i["key"]: i for i in client.get("/api/firewall", headers=client.view).json()["items"]}
    assert items["youtube"]["action"] == "bloquear" and items["spotify"]["action"] == "permitir"
    assert client.put("/api/firewall/no-existe", headers=client.adm, json={"action": "alertar"}).status_code == 404


def test_firewall_custom_rule_lifecycle(client):
    assert client.post("/api/firewall/custom", headers=client.adm, json={"label": "X", "pattern": "no es dominio"}).status_code == 400
    r = client.post("/api/firewall/custom", headers=client.adm, json={"label": "Mi sitio", "pattern": "https://www.Ejemplo-Test.com/ruta"})
    assert r.status_code == 200 and r.json()["key"] == "c_ejemplo-test-com"
    assert client.post("/api/firewall/custom", headers=client.adm, json={"label": "Otra", "pattern": "ejemplo-test.com"}).status_code == 400  # duplicada
    assert any(i["key"] == "c_ejemplo-test-com" and i["custom"] for i in client.get("/api/firewall", headers=client.view).json()["items"])
    assert client.delete("/api/firewall/custom/c_ejemplo-test-com", headers=client.adm).status_code == 200
    assert not any(i["custom"] for i in client.get("/api/firewall", headers=client.view).json()["items"])
