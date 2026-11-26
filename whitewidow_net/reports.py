"""Informes de sesión de monitoreo (HTML autónomo) y exportaciones CSV/JSON."""
import csv
import html
import io
import json
import time

from . import __version__


def _t(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


def csv_safe(v):
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(rows):
    buf = io.StringIO()
    if rows:
        w = csv.writer(buf)
        w.writerow(rows[0].keys())
        for r in rows:
            w.writerow([csv_safe(v) for v in r.values()])
    return buf.getvalue()


def _table(headers, rows):
    h = "".join(f"<th>{html.escape(x)}</th>" for x in headers)
    b = "".join("<tr>" + "".join(f"<td>{html.escape(str(c if c is not None else ''))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{h}</tr></thead><tbody>{b or '<tr><td colspan=99>Sin datos</td></tr>'}</tbody></table>"


def build_html(db, network_id=None):
    nets = db.query("SELECT * FROM networks WHERE id=?", (network_id,)) if network_id else db.query("SELECT * FROM networks")
    parts = []
    for n in nets:
        nid = n["id"]
        devs = db.query("SELECT * FROM devices WHERE network_id=? ORDER BY ip", (nid,))
        alerts = db.query("SELECT * FROM alerts WHERE network_id=? OR network_id IS NULL ORDER BY ts DESC LIMIT 200", (nid,))
        scans = db.query("SELECT * FROM scans WHERE network_id=? ORDER BY ts_start", (nid,))
        acts = db.query("SELECT a.*, d.ip FROM device_activity a JOIN devices d ON d.id=a.device_id WHERE d.network_id=? ORDER BY a.ts DESC LIMIT 300", (nid,))
        span = f"{_t(scans[0]['ts_start'])} → {_t(scans[-1]['ts_end'])}" if scans else "sin escaneos"
        parts.append(f"""<h2>{html.escape(n['name'] or '')}</h2>
<p>Subred {html.escape(n['subnet'] or '')} · Gateway {html.escape(n['gateway_ip'] or '')} ({html.escape(n['gateway_mac'] or 'MAC no disponible')}) · SSID {html.escape(n['ssid'] or '-')} · Autorizada: {'sí' if n['authorized'] else 'no (solo modo pasivo)'}</p>
<p>Periodo cubierto: {span} · Escaneos: {len(scans)} · Dispositivos: {len(devs)}</p>
<h3>Dispositivos</h3>{_table(['IP','MAC','Fabricante','Hostname','Tipo (estimado)','SO (estimado)','Puertos','En línea','Primera vez','Última vez'],
  [[d['ip'], d['mac'], d['vendor'], d['hostname'], d['dtype'], d['os_guess'], d['ports'], 'sí' if d['online'] else 'no', _t(d['first_seen']), _t(d['last_seen'])] for d in devs])}
<h3>Alertas (indicios, no confirmaciones)</h3>{_table(['Fecha','Severidad','Regla','Título','Estado'], [[_t(a['ts']), a['severity'], a['rule'], a['title'], a['status']] for a in alerts])}
<h3>Cambios de actividad de dispositivos</h3>{_table(['Fecha','IP','Evento','Detalle'], [[_t(a['ts']), a['ip'], a['event'], a['detail']] for a in acts])}""")
    top = db.query("SELECT raddr, rport, COUNT(*) n, SUM(count) obs, MAX(process) proc FROM connections WHERE direction='outbound' AND raddr!='' GROUP BY raddr, rport ORDER BY obs DESC LIMIT 25")
    parts.append("<h2>Destinos más frecuentes (este equipo)</h2>" + _table(['Destino', 'Puerto', 'Conexiones', 'Observaciones', 'Proceso'], [[t['raddr'], t['rport'], t['n'], t['obs'], t['proc']] for t in top]))
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Informe WhiteWidow Net</title>
<style>body{{font:14px system-ui,sans-serif;margin:2rem;color:#111}}table{{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}}td,th{{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:12px}}th{{background:#eee}}h1,h2{{border-bottom:2px solid #222}}.note{{background:#fff7d6;padding:.6rem;border:1px solid #e0c96a}}</style></head><body>
<h1>Informe de monitoreo — WhiteWidow Net v{__version__}</h1><p>Generado: {_t(time.time())}</p>
<p class="note">Los tipos de dispositivo, sistemas operativos y clasificaciones de dominios son <b>estimaciones</b>. Las alertas son indicios que requieren verificación. Con HTTPS solo se observan dominios, no URLs completas. Este informe cubre únicamente redes donde el operador declaró autorización.</p>
{''.join(parts)}</body></html>"""


def evidence_json(db, device_id):
    d = db.one("SELECT * FROM devices WHERE id=?", (device_id,))
    if not d:
        return None
    return {"exportado": int(time.time()), "dispositivo": d,
            "actividad": db.query("SELECT * FROM device_activity WHERE device_id=? ORDER BY ts", (device_id,)),
            "alertas": db.query("SELECT * FROM alerts WHERE device_id=? ORDER BY ts", (device_id,)),
            "dominios": db.query("SELECT * FROM domains WHERE device_id=? ORDER BY last_seen DESC", (device_id,)),
            "conexiones": db.query("SELECT * FROM connections WHERE device_id=? ORDER BY ts_last DESC LIMIT 1000", (device_id,))}


def session_json(db, since=0):
    """Instantánea completa de lo registrado desde `since` (epoch). Se guarda al detener una grabación."""
    import json as _j
    alerts = db.query("SELECT * FROM alerts WHERE ts>=? ORDER BY ts", (since,))
    for a in alerts:
        try:
            a["evidence"] = _j.loads(a["evidence"])
        except (TypeError, ValueError):
            pass
    return {"version": __version__, "desde": since, "hasta": int(time.time()),
            "redes": db.query("SELECT * FROM networks"),
            "dispositivos": db.query("SELECT * FROM devices"),
            "actividad_dispositivos": db.query("SELECT * FROM device_activity WHERE ts>=? ORDER BY ts", (since,)),
            "conexiones": db.query("SELECT * FROM connections WHERE ts_last>=? ORDER BY ts_first", (since,)),
            "dominios": db.query("SELECT * FROM domains WHERE last_seen>=?", (since,)),
            "procesos": db.query("SELECT * FROM processes WHERE last_seen>=?", (since,)),
            "trafico": db.query("SELECT ts,interface,rx_rate,tx_rate FROM traffic WHERE ts>=? ORDER BY ts", (since,)),
            "alertas": alerts,
            "eventos_red": db.query("SELECT * FROM net_events WHERE ts_last>=? ORDER BY ts", (since,)),
            "escaneos": db.query("SELECT * FROM scans WHERE ts_start>=? ORDER BY ts_start", (since,)),
            "auditoria": db.query("SELECT * FROM audit WHERE ts>=? ORDER BY ts", (since,))}
