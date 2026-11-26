"""Detección del entorno de red. Usa /proc y psutil primero (sin privilegios); `ip`, `iwgetid`, `nmcli`
y `resolvectl` solo como complemento."""
import ipaddress
import os
import re
import shutil
import socket
import subprocess
from typing import Optional

import psutil


def run(cmd, timeout=3) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def norm_mac(mac: Optional[str]) -> str:
    return (mac or "").lower().replace("-", ":").strip()


def default_route():
    """Devuelve (interfaz, gateway) de la ruta por defecto con menor métrica."""
    best = None
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 8 and p[1] == "00000000" and int(p[3], 16) & 2:
                    gw = socket.inet_ntoa(int(p[2], 16).to_bytes(4, "little"))
                    metric = int(p[6])
                    if best is None or metric < best[2]:
                        best = (p[0], gw, metric)
    except OSError:
        pass
    return (best[0], best[1]) if best else (None, None)


def neighbors() -> dict:
    """Tabla ARP/vecinos del kernel: {ip: mac}. Lectura pasiva, no envía tráfico."""
    out = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                p = line.split()
                if len(p) >= 4 and int(p[2], 16) & 2 and p[3] != "00:00:00:00:00:00":
                    out[p[0]] = norm_mac(p[3])
    except OSError:
        pass
    return out


def wifi_ssid(iface: str) -> str:
    if not iface or not iface.startswith(("wl", "wlan")):
        return ""
    s = run(["iwgetid", "-r"]).strip()
    if s:
        return s
    for line in run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).splitlines():
        if line.startswith("yes:") or line.startswith("sí:"):
            return line.split(":", 1)[1]
    return ""


def dns_servers() -> list:
    servers = []
    try:
        for line in open("/etc/resolv.conf"):
            m = re.match(r"\s*nameserver\s+(\S+)", line)
            if m:
                servers.append(m.group(1))
    except OSError:
        pass
    if any(s.startswith("127.") for s in servers):  # systemd-resolved: buscar los reales
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", run(["resolvectl", "dns"]))
        real = [x for x in found if not x.startswith("127.")]
        if real:
            servers = real
    seen, out = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def detect() -> dict:
    """Devuelve las señales de la red actual. `connected` es False si no hay ruta por defecto."""
    forced = os.environ.get("WW_FORCE_CIDR")  # solo para pruebas/laboratorio
    if forced:
        ifc = ipaddress.ip_interface(forced)
        return {"connected": True, "interface": "test0", "ip": str(ifc.ip), "gateway": os.environ.get("WW_FORCE_GW", ""),
                "gateway_mac": os.environ.get("WW_FORCE_GW_MAC", ""), "subnet": str(ifc.network), "prefix": ifc.network.prefixlen,
                "ssid": os.environ.get("WW_FORCE_SSID", ""), "dns": [], "iface_mac": ""}
    iface, gw = default_route()
    if not iface:
        return {"connected": False}
    ip = mask = mac = None
    for a in psutil.net_if_addrs().get(iface, []):
        if a.family == socket.AF_INET:
            ip, mask = a.address, a.netmask
        elif a.family == psutil.AF_LINK:
            mac = norm_mac(a.address)
    if not ip or not mask:
        return {"connected": False}
    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    gw_mac = neighbors().get(gw, "")
    if gw and not gw_mac:  # forzar resolución ARP del gateway con un único intento TCP
        try:
            socket.create_connection((gw, 80), timeout=0.5).close()
        except OSError:
            pass
        gw_mac = neighbors().get(gw, "")
    return {"connected": True, "interface": iface, "ip": ip, "gateway": gw or "", "gateway_mac": gw_mac,
            "subnet": str(net), "prefix": net.prefixlen, "ssid": wifi_ssid(iface), "dns": dns_servers(), "iface_mac": mac or ""}


def signature(sig: dict) -> str:
    return "|".join(str(sig.get(k, "")) for k in ("interface", "ip", "gateway", "gateway_mac", "subnet", "ssid")) + "|" + ",".join(sig.get("dns", []))
