"""Reconocimiento de redes con múltiples señales (no solo SSID o IP) y gestión de perfiles."""
import json
import time

from . import detection

STRONG = 5  # puntaje mínimo para considerar la misma red


def score(net: dict, sig: dict, neighbor_macs=()) -> int:
    s = 0
    if sig.get("gateway_mac") and net.get("gateway_mac") == sig["gateway_mac"]:
        s += 5
    if sig.get("subnet") and net.get("subnet") == sig["subnet"]:
        s += 1
    if sig.get("ssid") and net.get("ssid") == sig["ssid"]:
        s += 1
    if sig.get("gateway") and net.get("gateway_ip") == sig["gateway"]:
        s += 1
    try:
        if set(json.loads(net.get("dns") or "[]")) & set(sig.get("dns", [])):
            s += 1
    except ValueError:
        pass
    return s


def identify(db, sig: dict, neighbor_macs=()):
    """Devuelve (red, es_nueva, puntaje). Crea un perfil si no hay coincidencia suficiente."""
    now = int(time.time())
    best, best_score = None, -1
    for n in db.query("SELECT * FROM networks"):
        sc = score(n, sig)
        known = {d["mac"] for d in db.query("SELECT mac FROM devices WHERE network_id=?", (n["id"],))}
        if len(known & set(neighbor_macs)) >= 2:  # dispositivos conocidos reaparecen
            sc += 2
        if sc > best_score:
            best, best_score = n, sc
    gw_mac = sig.get("gateway_mac", "")
    no_macs = best is not None and not gw_mac and not best["gateway_mac"]  # sin MAC de gateway en ninguna de las dos
    matched = best is not None and (best_score >= STRONG or (no_macs and best_score >= 3)
                                    or (best_score >= 4 and best["gateway_mac"] != gw_mac))
    if matched:
        if gw_mac and best["gateway_mac"] and best["gateway_mac"] != gw_mac:
            detection.raise_alert(db, "GATEWAY_MAC_CHANGED", "medium", "Cambió la MAC del gateway",
                                  "La red se reconoció por otras señales pero el gateway tiene otra MAC. Puede ser un cambio legítimo de router o un intento de suplantación (ARP spoofing).",
                                  {"anterior": best["gateway_mac"], "actual": gw_mac, "gateway": sig.get("gateway")},
                                  network_id=best["id"], dedupe_key=f"gwmac:{best['id']}:{gw_mac}")
        db.execute("UPDATE networks SET last_seen=?,gateway_mac=COALESCE(NULLIF(?,''),gateway_mac),gateway_ip=?,subnet=?,ssid=COALESCE(NULLIF(?,''),ssid),dns=?,interface=? WHERE id=?",
                   (now, gw_mac, sig.get("gateway"), sig.get("subnet"), sig.get("ssid"), json.dumps(sig.get("dns", [])), sig.get("interface"), best["id"]))
        return db.one("SELECT * FROM networks WHERE id=?", (best["id"],)), False, best_score
    name = sig.get("ssid") or f"Red {sig.get('subnet')}"
    nid = db.execute("INSERT INTO networks(name,kind,gateway_mac,gateway_ip,subnet,ssid,dns,interface,authorized,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,0,?,?)",
                     (name, "custom", gw_mac, sig.get("gateway"), sig.get("subnet"), sig.get("ssid"), json.dumps(sig.get("dns", [])), sig.get("interface"), now, now))
    db.audit("system", "network_profile_created", name, f"subnet={sig.get('subnet')} gw={sig.get('gateway')}")
    return db.one("SELECT * FROM networks WHERE id=?", (nid,)), True, best_score if best else 0
