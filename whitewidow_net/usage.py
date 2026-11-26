"""Resumen del tráfico de la interfaz en bytes (MB/GB) por periodo, hora y día.

Parte de los contadores acumulados de la interfaz (rx_bytes/tx_bytes) que se guardan cada pocos segundos. Es el tráfico
de ESTE equipo: una computadora conectada normalmente no recibe el tráfico de los demás dispositivos.
"""
from datetime import datetime

GAP_MAX = 120  # segundos: si hubo un hueco mayor (la app estuvo apagada) no se atribuye el delta a ningún periodo


def deltas(rows):
    """Genera (ts, bytes_bajada, bytes_subida) entre muestras consecutivas de la misma interfaz."""
    prev = None
    for r in rows:
        if prev and prev["interface"] == r["interface"] and 0 < r["ts"] - prev["ts"] <= GAP_MAX:
            rx, tx = r["rx_bytes"] - prev["rx_bytes"], r["tx_bytes"] - prev["tx_bytes"]
            yield r["ts"], (rx if rx >= 0 else r["rx_bytes"]), (tx if tx >= 0 else r["tx_bytes"])  # contador reiniciado
        prev = r


def _floor(ts, unit):
    d = datetime.fromtimestamp(ts)
    d = d.replace(minute=0, second=0, microsecond=0) if unit == "hour" else d.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(d.timestamp())


def summarize(rows, now):
    """`rows`: filas de la tabla traffic ordenadas por ts (idealmente los últimos 7 días)."""
    today0 = _floor(now, "day")
    out = {"last_hour": [0, 0], "today": [0, 0], "last_24h": [0, 0], "last_7d": [0, 0]}
    hours, days = {}, {}
    for ts, rx, tx in deltas(rows):
        age = now - ts
        for key, ok in (("last_hour", age <= 3600), ("today", ts >= today0), ("last_24h", age <= 86400), ("last_7d", age <= 7 * 86400)):
            if ok:
                out[key][0] += rx
                out[key][1] += tx
        if age <= 24 * 3600:
            h = hours.setdefault(_floor(ts, "hour"), [0, 0])
            h[0] += rx
            h[1] += tx
        d = days.setdefault(_floor(ts, "day"), [0, 0])
        d[0] += rx
        d[1] += tx
    res = {k: {"rx": v[0], "tx": v[1], "total": v[0] + v[1]} for k, v in out.items()}
    res["hours"] = [{"ts": t, "rx": v[0], "tx": v[1]} for t, v in sorted(hours.items())]
    res["days"] = [{"ts": t, "rx": v[0], "tx": v[1]} for t, v in sorted(days.items())][-7:]
    res["since"] = rows[0]["ts"] if rows else None
    return res
