"""Reglas de detección. Cada alerta incluye regla, evidencia y estado de investigación.
Una alerta es un indicio, nunca una confirmación de malware."""
import json
import math
import statistics
import time
from collections import deque

RISKY_PORTS = {21: "FTP (sin cifrar)", 23: "Telnet (sin cifrar)", 445: "SMB", 3389: "RDP", 5900: "VNC", 1883: "MQTT sin TLS"}
SUSPICIOUS_TLDS = {"tk", "gq", "ml", "cf", "ga", "top", "zip", "mov"}
_tx_hist = deque(maxlen=120)


def raise_alert(db, rule, severity, title, description, evidence, device_id=None, network_id=None,
                dedupe_key=None, window=3600):
    """Crea una alerta salvo que exista una igual (dedupe_key) dentro de la ventana. Devuelve id o None."""
    now = int(time.time())
    if dedupe_key:
        if db.one("SELECT id FROM alerts WHERE dedupe_key=? AND ts>?", (dedupe_key, now - window)):
            return None
    return db.execute(
        "INSERT INTO alerts(ts,rule,severity,device_id,network_id,title,description,evidence,status,dedupe_key) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (now, rule, severity, device_id, network_id, title, description, json.dumps(evidence, default=str), "open", dedupe_key))


def check_risky_ports(db, device, ports, network_id):
    for p in ports:
        if p in RISKY_PORTS:
            raise_alert(db, "RISKY_PORT_OPEN", "medium" if p in (23, 3389, 5900) else "low",
                        f"Puerto {p} abierto en {device.get('ip')}",
                        f"El dispositivo expone {RISKY_PORTS[p]}. Revisa si es necesario y si está protegido.",
                        {"ip": device.get("ip"), "mac": device.get("mac"), "port": p},
                        device_id=device.get("id"), network_id=network_id, dedupe_key=f"risky:{device.get('id')}:{p}", window=86400)


def beacon_stats(timestamps):
    """Devuelve (media, desviación, coef. variación) de los intervalos, o None si no hay datos suficientes."""
    ts = sorted(timestamps)
    if len(ts) < 8:
        return None
    iv = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
    if len(iv) < 7:
        return None
    mean = statistics.fmean(iv)
    sd = statistics.pstdev(iv)
    return mean, sd, (sd / mean if mean else 9.9)


def check_beaconing(db, dest, port, network_id=None, device_id=None):
    now = int(time.time())
    rows = db.query("SELECT ts FROM conn_sessions WHERE dest=? AND port=? AND ts>?", (dest, port, now - 6 * 3600))
    st = beacon_stats([r["ts"] for r in rows])
    if not st:
        return
    mean, sd, cv = st
    if mean >= 30 and cv < 0.2:  # >=30s para evitar artefactos del muestreo
        raise_alert(db, "BEACONING_PATTERN", "medium", f"Conexiones periódicas hacia {dest}:{port}",
                    "Patrón de intervalos regulares compatible con beaconing. También lo producen actualizaciones, NTP y keep-alives legítimos; verifica el proceso antes de concluir.",
                    {"destino": dest, "puerto": port, "sesiones": len(rows), "intervalo_medio_s": round(mean, 1), "desviacion_s": round(sd, 1), "cv": round(cv, 3)},
                    device_id=device_id, network_id=network_id, dedupe_key=f"beacon:{dest}:{port}", window=6 * 3600)


def check_traffic_spike(db, tx_rate, network_id=None):
    hist = list(_tx_hist)
    _tx_hist.append(tx_rate)
    if len(hist) < 30:
        return
    mean = statistics.fmean(hist)
    sd = statistics.pstdev(hist)
    if tx_rate > 1_000_000 and tx_rate > mean + 4 * max(sd, 1):
        raise_alert(db, "TRAFFIC_SPIKE", "low", "Aumento inusual de tráfico saliente",
                    "La tasa de subida supera 4 desviaciones estándar sobre la línea base reciente. Puede ser una copia de seguridad o subida legítima.",
                    {"tx_bytes_s": round(tx_rate), "media": round(mean), "desviacion": round(sd)}, network_id=network_id,
                    dedupe_key="spike", window=900)


def entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def check_domain(db, domain):
    """Devuelve el motivo si el dominio es sospechoso (clasificación estimada) o None."""
    d = domain.lower().rstrip(".")
    if db.one("SELECT 1 FROM blocklist WHERE domain=?", (d,)):
        return "en lista de bloqueo"
    labels = d.split(".")
    if labels[-1] in SUSPICIOUS_TLDS:
        return f"TLD de alto abuso (.{labels[-1]})"
    longest = max(labels[:-1] or labels, key=len)
    if len(longest) >= 16 and entropy(longest) > 3.5:
        return "etiqueta larga de alta entropía (posible DGA, estimado)"
    return None


def check_portscan_inbound(db, conns, local_ips, network_id=None):
    """Origen remoto que toca >=10 puertos locales distintos en la instantánea actual."""
    by_src = {}
    for c in conns:
        if c["direction"] == "inbound" and c["raddr"]:
            by_src.setdefault(c["raddr"], set()).add(c["lport"])
    for src, ports in by_src.items():
        if len(ports) >= 10:
            raise_alert(db, "PORT_SCAN_INBOUND", "high", f"Posible escaneo de puertos desde {src}",
                        "Un mismo origen contactó muchos puertos distintos de este equipo.",
                        {"origen": src, "puertos": sorted(ports)[:50]}, network_id=network_id, dedupe_key=f"pscan:{src}", window=1800)
