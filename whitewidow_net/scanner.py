"""Motor de descubrimiento. Solo escanea rangos privados, con tope de hosts, y únicamente con permiso explícito."""
import asyncio
import ipaddress
import shutil
import socket

from . import netinfo, oui

COMMON_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 443: "https", 139: "netbios", 445: "smb",
                554: "rtsp", 631: "ipp", 1883: "mqtt", 3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt",
                9100: "impresora", 62078: "iphone-sync"}


class ScanRefused(Exception):
    pass


def validate_target(cidr: str, max_hosts: int = 1024):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ScanRefused("Solo IPv4 en esta versión.")
    if not (net.is_private or net.is_link_local):
        raise ScanRefused(f"{net} no es un rango privado: se rechaza el escaneo.")
    if net.num_addresses > max_hosts + 2:
        raise ScanRefused(f"{net} excede el máximo de {max_hosts} hosts.")
    return net


async def _ping(ip, sem):
    if not shutil.which("ping"):
        return False
    async with sem:
        try:
            p = await asyncio.create_subprocess_exec("ping", "-c", "1", "-W", "1", ip,
                                                     stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            return (await asyncio.wait_for(p.wait(), 3)) == 0
        except (asyncio.TimeoutError, OSError):
            return False


async def _tcp(ip, port, sem, timeout=0.6):
    """Devuelve 'open', 'refused' (host vivo) o None."""
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close()
            return "open"
        except ConnectionRefusedError:
            return "refused"
        except (asyncio.TimeoutError, OSError):
            return None


async def _probe(ip, sem):
    if await _ping(ip, sem):
        return True
    for port in (443, 80):
        if await _tcp(ip, port, sem) in ("open", "refused"):
            return True
    return False


async def _rdns(ip):
    try:
        return (await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), 2))[0]
    except (asyncio.TimeoutError, OSError):
        return ""


async def scan_async(cidr, max_hosts=1024, port_scan=True, active=True):
    net = validate_target(cidr, max_hosts)
    hosts = [str(h) for h in net.hosts()]
    alive = set()
    if active:
        sem = asyncio.Semaphore(128)
        res = await asyncio.gather(*[_probe(h, sem) for h in hosts])
        alive |= {h for h, ok in zip(hosts, res) if ok}
    neigh = netinfo.neighbors()
    for ip, mac in neigh.items():
        if ip in hosts:
            alive.add(ip)
    ports = {}
    if active and port_scan and alive:
        sem = asyncio.Semaphore(256)
        ips = sorted(alive)
        jobs = [(ip, p) for ip in ips for p in COMMON_PORTS]
        res = await asyncio.gather(*[_tcp(ip, p, sem) for ip, p in jobs])
        for (ip, p), r in zip(jobs, res):
            if r == "open":
                ports.setdefault(ip, []).append(p)
    order = sorted(alive, key=ipaddress.ip_address)
    names = await asyncio.gather(*[_rdns(ip) for ip in order]) if active else [""] * len(order)
    out = [{"ip": ip, "mac": neigh.get(ip, ""), "hostname": n, "ports": sorted(ports.get(ip, []))} for ip, n in zip(order, names)]
    return out


def scan(cidr, **kw):
    return asyncio.run(scan_async(cidr, **kw))


def classify(mac, vendor, hostname, ports, is_gateway, is_self):
    """Tipo y SO estimados (siempre heurísticos, nunca confirmados)."""
    v, h, p = (vendor or "").lower(), (hostname or "").lower(), set(ports or [])
    if is_gateway:
        return "Router / gateway", ""
    if is_self:
        return "Este equipo", ""
    os_guess = ""
    if 3389 in p or (445 in p and 139 in p):
        os_guess = "Windows (estimado)"
    elif 62078 in p:
        os_guess = "iOS (estimado)"
    elif 22 in p and not p & {445, 3389}:
        os_guess = "Linux/Unix (estimado)"
    if p & {9100, 631}:
        return "Impresora", os_guess
    if 554 in p:
        return "Cámara IP / NVR", os_guess
    if "raspberry" in v:
        return "Raspberry Pi", "Linux (estimado)"
    if "espressif" in v or 1883 in p:
        return "Dispositivo IoT", os_guess
    if "apple" in v or 62078 in p:
        return "Dispositivo Apple", os_guess
    if any(x in v for x in ("vmware", "virtualbox", "qemu", "hyper-v")):
        return "Máquina virtual", os_guess
    if "aleatoria" in v:
        return "Móvil/tablet probable (MAC aleatoria)", os_guess
    if any(x in h for x in ("iphone", "ipad", "android", "galaxy", "pixel")):
        return "Móvil/tablet", os_guess
    if 3389 in p or 445 in p:
        return "PC / servidor", os_guess
    return "Desconocido", os_guess
