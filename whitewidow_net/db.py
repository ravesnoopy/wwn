"""Almacenamiento persistente SQLite (WAL). El esquema usa SQL estándar para facilitar migrar a PostgreSQL."""
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS networks(
  id INTEGER PRIMARY KEY, name TEXT, kind TEXT DEFAULT 'custom', gateway_mac TEXT, gateway_ip TEXT,
  subnet TEXT, ssid TEXT, dns TEXT, interface TEXT, authorized INTEGER DEFAULT 0,
  first_seen INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY, network_id INTEGER, mac TEXT, ip TEXT, vendor TEXT, hostname TEXT,
  dtype TEXT, os_guess TEXT, owner TEXT, label TEXT, trusted INTEGER DEFAULT 0, online INTEGER DEFAULT 1,
  first_seen INTEGER, last_seen INTEGER, ports TEXT DEFAULT '[]', random_mac INTEGER DEFAULT 0,
  is_self INTEGER DEFAULT 0, is_gateway INTEGER DEFAULT 0, services TEXT DEFAULT '[]', dhcp_vendor TEXT, dhcp_fp TEXT,
  UNIQUE(network_id, mac));
CREATE TABLE IF NOT EXISTS device_activity(
  id INTEGER PRIMARY KEY, device_id INTEGER, ts INTEGER, event TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_act_dev ON device_activity(device_id, ts);
CREATE TABLE IF NOT EXISTS connections(
  id INTEGER PRIMARY KEY, ckey TEXT UNIQUE, network_id INTEGER, device_id INTEGER, ts_first INTEGER, ts_last INTEGER,
  count INTEGER DEFAULT 1, proto TEXT, laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER, status TEXT,
  direction TEXT, pid INTEGER, process TEXT);
CREATE INDEX IF NOT EXISTS ix_conn_last ON connections(ts_last);
CREATE TABLE IF NOT EXISTS conn_sessions(id INTEGER PRIMARY KEY, dest TEXT, port INTEGER, ts INTEGER);
CREATE INDEX IF NOT EXISTS ix_sess ON conn_sessions(dest, port, ts);
CREATE TABLE IF NOT EXISTS domains(
  id INTEGER PRIMARY KEY, domain TEXT, device_id INTEGER DEFAULT 0, first_seen INTEGER, last_seen INTEGER,
  count INTEGER DEFAULT 1, category TEXT, source TEXT, UNIQUE(domain, device_id));
CREATE TABLE IF NOT EXISTS processes(
  id INTEGER PRIMARY KEY, name TEXT, exe TEXT, username TEXT, first_seen INTEGER, last_seen INTEGER,
  conn_count INTEGER DEFAULT 0, suspicious INTEGER DEFAULT 0, reason TEXT, UNIQUE(name, exe));
CREATE TABLE IF NOT EXISTS traffic(ts INTEGER, interface TEXT, rx_bytes INTEGER, tx_bytes INTEGER, rx_rate REAL, tx_rate REAL);
CREATE INDEX IF NOT EXISTS ix_traffic ON traffic(ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY, ts INTEGER, rule TEXT, severity TEXT, device_id INTEGER, network_id INTEGER,
  title TEXT, description TEXT, evidence TEXT, status TEXT DEFAULT 'open', dedupe_key TEXT);
CREATE INDEX IF NOT EXISTS ix_alert_key ON alerts(dedupe_key, ts);
CREATE TABLE IF NOT EXISTS policies(
  id INTEGER PRIMARY KEY, ts INTEGER, network_id INTEGER, action TEXT, target TEXT, params TEXT,
  state TEXT, expires_at INTEGER, adapter TEXT, actor TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER, actor TEXT, action TEXT, target TEXT, detail TEXT, ok INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS net_events(
  id INTEGER PRIMARY KEY, ekey TEXT UNIQUE, ts INTEGER, ts_last INTEGER, kind TEXT, src_ip TEXT, src_mac TEXT, dst_ip TEXT,
  dst_port INTEGER, count INTEGER DEFAULT 1, detail TEXT, network_id INTEGER);
CREATE INDEX IF NOT EXISTS ix_ev ON net_events(ts_last);
CREATE TABLE IF NOT EXISTS sniffer_state(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS blocklist(domain TEXT PRIMARY KEY, ts INTEGER);
CREATE TABLE IF NOT EXISTS ip_names(ip TEXT PRIMARY KEY, domain TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS domain_visits(
  id INTEGER PRIMARY KEY, device_id INTEGER DEFAULT 0, gkey TEXT, glabel TEXT, gkind TEXT, domain TEXT,
  ts_start INTEGER, ts_last INTEGER, hits INTEGER DEFAULT 1, nth INTEGER DEFAULT 1);
CREATE INDEX IF NOT EXISTS ix_visits ON domain_visits(gkey, device_id, ts_last);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, network_id INTEGER, ts_start INTEGER, ts_end INTEGER, mode TEXT, hosts_found INTEGER, detail TEXT);
"""


class DB:
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(devices)")}  # migración desde v1.0.x / v1.1.x
            for c, d in (("services", "TEXT DEFAULT '[]'"), ("dhcp_vendor", "TEXT"), ("dhcp_fp", "TEXT"), ("user_type", "TEXT")):
                if c not in cols:
                    self.conn.execute(f"ALTER TABLE devices ADD COLUMN {c} {d}")
            if "parent" not in {r[1] for r in self.conn.execute("PRAGMA table_info(processes)")}:
                self.conn.execute("ALTER TABLE processes ADD COLUMN parent TEXT")
            self.conn.commit()

    def execute(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid

    def query(self, sql, params=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def audit(self, actor, action, target="", detail="", ok=True):
        self.execute("INSERT INTO audit(ts,actor,action,target,detail,ok) VALUES(?,?,?,?,?,?)",
                     (int(time.time()), actor, action, str(target), str(detail)[:2000], 1 if ok else 0))

    def set_state(self, key, value):
        self.execute("INSERT INTO sniffer_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def get_state(self):
        return {r["key"]: r["value"] for r in self.query("SELECT key,value FROM sniffer_state")}

    def purge(self, days):
        cutoff = int(time.time()) - days * 86400
        for sql in ("DELETE FROM connections WHERE ts_last<?", "DELETE FROM conn_sessions WHERE ts<?",
                    "DELETE FROM traffic WHERE ts<?", "DELETE FROM device_activity WHERE ts<?",
                    "DELETE FROM domains WHERE last_seen<?", "DELETE FROM ip_names WHERE ts<?", "DELETE FROM net_events WHERE ts_last<?", "DELETE FROM alerts WHERE ts<? AND status!='open'"):
            self.execute(sql, (cutoff,))

    def close(self):
        with self.lock:
            self.conn.close()
