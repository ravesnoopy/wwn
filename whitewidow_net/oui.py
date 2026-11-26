"""Identificación de fabricante por prefijo MAC (OUI). Usa las bases del sistema si existen
(ieee-data, nmap) y una tabla mínima interna como respaldo."""
import re
from pathlib import Path

BUILTIN = {
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "005056": "VMware", "000C29": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM", "00155D": "Microsoft Hyper-V",
    "000393": "Apple", "000A95": "Apple", "3C0754": "Apple", "00000C": "Cisco",
    "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti",
    "240AC4": "Espressif", "30AEA4": "Espressif", "84CCA8": "Espressif",
    "001B21": "Intel", "00095B": "Netgear", "50C7BF": "TP-Link", "001132": "Synology",
}
_cache = None


def _load():
    global _cache
    if _cache is not None:
        return _cache
    table = dict(BUILTIN)
    for path in ("/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt"):
        p = Path(path)
        if p.exists():
            for line in p.read_text(errors="ignore").splitlines():
                m = re.match(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$", line)
                if m:
                    table["".join(m.groups()[:3])] = m.group(4).strip()
            break
    for path in ("/usr/share/nmap/nmap-mac-prefixes", "/usr/share/wireshark/manuf"):
        p = Path(path)
        if p.exists():
            for line in p.read_text(errors="ignore").splitlines():
                m = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                if m:
                    table.setdefault(m.group(1).upper(), m.group(2).strip())
    _cache = table
    return table


def is_random(mac: str) -> bool:
    """Bit 'localmente administrada': típico de MAC aleatoria (privacidad en móviles) o interfaces virtuales."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor(mac: str) -> str:
    if not mac or ":" not in mac:
        return ""
    if is_random(mac):
        return "MAC aleatoria/administrada localmente"
    return _load().get(mac.replace(":", "").upper()[:6], "")
