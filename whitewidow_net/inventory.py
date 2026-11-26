"""Persistencia del inventario de dispositivos a partir de resultados de escaneo."""
import json
import time

from . import detection, fingerprint, oui, scanner


def _event(db, dev_id, event, detail=""):
    db.execute("INSERT INTO device_activity(device_id,ts,event,detail) VALUES(?,?,?,?)", (dev_id, int(time.time()), event, detail))


def persist(db, network, results, sig, mode, mark_offline):
    """Actualiza dispositivos. Devuelve el número de dispositivos nuevos."""
    now = int(time.time())
    nid = network["id"]
    first_scan = db.one("SELECT COUNT(*) c FROM scans WHERE network_id=?", (nid,))["c"] == 0
    seen_ids, new = set(), 0
    for r in results:
        mac = r["mac"] or f"ip:{r['ip']}"
        is_gw = r["ip"] == sig.get("gateway")
        is_self = r["ip"] == sig.get("ip")
        row = db.one("SELECT * FROM devices WHERE network_id=? AND mac=?", (nid, mac))
        ven = oui.vendor(r["mac"])
        if row is None:
            dtype, osg = scanner.classify(mac, ven, r["hostname"], r["ports"], is_gw, is_self)
            did = db.execute("INSERT INTO devices(network_id,mac,ip,vendor,hostname,dtype,os_guess,online,first_seen,last_seen,ports,random_mac,is_self,is_gateway) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             (nid, mac, r["ip"], ven, r["hostname"], dtype, osg, 1, now, now, json.dumps(r["ports"]),
                              1 if oui.is_random(r["mac"]) else 0, int(is_self), int(is_gw)))
            _event(db, did, "discovered", f"ip={r['ip']}")
            new += 1
            if not first_scan and not is_self:
                detection.raise_alert(db, "NEW_DEVICE", "low", f"Dispositivo nuevo: {r['ip']}",
                                      "Apareció un dispositivo no visto antes en esta red. Verifica que lo reconoces.",
                                      {"ip": r["ip"], "mac": mac, "fabricante": ven, "tipo_estimado": dtype}, device_id=did,
                                      network_id=nid, dedupe_key=f"new:{nid}:{mac}", window=86400 * 365)
        else:
            did = row["id"]
            if row["ip"] != r["ip"]:
                _event(db, did, "ip_changed", f"{row['ip']} -> {r['ip']}")
            if not row["online"]:
                _event(db, did, "online")
            old_ports = set(json.loads(row["ports"] or "[]"))
            ports = sorted(set(r["ports"]) | (old_ports if mode == "passive" else set()))
            if set(ports) != old_ports:
                _event(db, did, "ports_changed", f"{sorted(old_ports)} -> {ports}")
            dtype, osg = scanner.classify(mac, ven or row["vendor"], r["hostname"] or row["hostname"], ports, is_gw, is_self)
            dtype, osg = fingerprint.refine(dtype, osg, json.loads(row["services"] or "[]"), row["dhcp_vendor"], row["dhcp_fp"])
            db.execute("UPDATE devices SET ip=?,vendor=COALESCE(NULLIF(?,''),vendor),hostname=COALESCE(NULLIF(?,''),hostname),dtype=?,os_guess=?,online=1,last_seen=?,ports=?,is_self=?,is_gateway=? WHERE id=?",
                       (r["ip"], ven, r["hostname"], dtype, osg, now, json.dumps(ports), int(is_self), int(is_gw), did))
        seen_ids.add(did)
        detection.check_risky_ports(db, {"id": did, "ip": r["ip"], "mac": mac}, r["ports"], nid)
    if mark_offline:
        for d in db.query("SELECT id FROM devices WHERE network_id=? AND online=1", (nid,)):
            if d["id"] not in seen_ids:
                db.execute("UPDATE devices SET online=0 WHERE id=?", (d["id"],))
                _event(db, d["id"], "offline")
    db.execute("INSERT INTO scans(network_id,ts_start,ts_end,mode,hosts_found,detail) VALUES(?,?,?,?,?,?)",
               (nid, now, int(time.time()), mode, len(results), "baseline" if first_scan else ""))
    return new


def observe(db, network_id, mac, ip, hostname="", services=(), dhcp_vendor="", dhcp_fp="", gateway_ip="", self_ip=""):
    """Registra un dispositivo visto de forma PASIVA (ARP, DHCP, mDNS, SSDP, NetBIOS). Devuelve el id o None."""
    mac = (mac or "").lower()
    if not network_id or len(mac) != 17 or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or int(mac[:2], 16) & 1:
        return None
    now = int(time.time())
    ven = oui.vendor(mac)
    is_gw, is_self = bool(ip) and ip == gateway_ip, bool(ip) and ip == self_ip
    row = db.one("SELECT * FROM devices WHERE network_id=? AND mac=?", (network_id, mac))
    svc_new = [x[:90] for x in services]
    if row is None:
        svc = sorted(set(svc_new))[:40]
        dtype, osg = scanner.classify(mac, ven, hostname, [], is_gw, is_self)
        dtype, osg = fingerprint.refine(dtype, osg, svc, dhcp_vendor, dhcp_fp)
        did = db.execute("INSERT INTO devices(network_id,mac,ip,vendor,hostname,dtype,os_guess,online,first_seen,last_seen,ports,random_mac,is_self,is_gateway,services,dhcp_vendor,dhcp_fp) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (network_id, mac, ip, ven, hostname, dtype, osg, 1, now, now, "[]", int(oui.is_random(mac)), int(is_self), int(is_gw), json.dumps(svc), dhcp_vendor, dhcp_fp))
        _event(db, did, "discovered_passive", f"ip={ip}")
        if db.one("SELECT COUNT(*) c FROM scans WHERE network_id=?", (network_id,))["c"] > 0 and not is_self:
            detection.raise_alert(db, "NEW_DEVICE", "low", f"Dispositivo nuevo (escucha pasiva): {ip}",
                                  "Apareció un dispositivo no visto antes en esta red. Verifica que lo reconoces.",
                                  {"ip": ip, "mac": mac, "hostname": hostname, "fabricante": ven, "tipo_estimado": dtype}, device_id=did,
                                  network_id=network_id, dedupe_key=f"new:{network_id}:{mac}", window=86400 * 365)
        return did
    did = row["id"]
    if ip and row["ip"] != ip:
        _event(db, did, "ip_changed", f"{row['ip']} -> {ip}")
    if not row["online"]:
        _event(db, did, "online")
    svc = sorted(set(json.loads(row["services"] or "[]")) | set(svc_new))[:40]
    host = hostname or row["hostname"] or ""
    dv, dfp = dhcp_vendor or row["dhcp_vendor"] or "", dhcp_fp or row["dhcp_fp"] or ""
    dtype, osg = scanner.classify(mac, ven or row["vendor"], host, json.loads(row["ports"] or "[]"), bool(row["is_gateway"]) or is_gw, bool(row["is_self"]) or is_self)
    dtype, osg = fingerprint.refine(dtype, osg, svc, dv, dfp)
    db.execute("UPDATE devices SET ip=COALESCE(NULLIF(?,''),ip),hostname=?,dtype=?,os_guess=?,online=1,last_seen=?,services=?,dhcp_vendor=?,dhcp_fp=? WHERE id=?",
               (ip, host, dtype, osg, now, json.dumps(svc), dv, dfp, did))
    return did
