import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WW_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("WW_CONFIG", str(tmp_path / "cfg" / "config.json"))
    for k in ("WW_FORCE_CIDR", "WW_FORCE_GW", "WW_FORCE_GW_MAC", "WW_FORCE_SSID"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


@pytest.fixture()
def db(env):
    from whitewidow_net.db import DB
    d = DB(env / "t.db")
    yield d
    d.close()
