"""Adaptador nftables. Bloquea IPs en la cadena `forward`: SOLO tiene efecto si este equipo es el gateway
(reenvío IP activo). No bloquea el tráfico de otros equipos en una red donde este equipo es un cliente más."""
import ipaddress
import os
import shutil
import subprocess

TABLE = "whitewidow"


class NftablesAdapter:
    name = "nftables"

    def __init__(self, cfg):
        self.cfg = cfg

    @staticmethod
    def forwarding() -> bool:
        try:
            return open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
        except OSError:
            return False

    def _prefix(self):
        return [] if os.geteuid() == 0 else ["sudo", "-n"]

    def _run(self, args):
        return subprocess.run(self._prefix() + ["nft"] + args, capture_output=True, text=True, timeout=10)

    def capabilities(self):
        if not shutil.which("nft"):
            return {"available": False, "reason": "nft no está instalado (sudo apt install nftables)"}
        try:
            ok = self._run(["--version"]).returncode == 0
        except (subprocess.SubprocessError, OSError):
            ok = False
        if not ok:
            return {"available": False, "reason": "sin permiso para ejecutar nft (instala con ./install.sh --with-control)"}
        fw = self.forwarding()
        return {"available": True, "actions": ["block_device", "unblock_device", "suspend_device"] if fw else [],
                "reason": "" if fw else "Este equipo no reenvía tráfico (no es el gateway): los bloqueos no afectarían a otros dispositivos."}

    def plan(self, action, ip):
        ipaddress.IPv4Address(ip)  # valida; lanza ValueError
        setup = [["add", "table", "inet", TABLE],
                 ["add", "set", "inet", TABLE, "blocked4", "{", "type", "ipv4_addr", ";", "}"],
                 ["add", "chain", "inet", TABLE, "forward", "{", "type", "filter", "hook", "forward", "priority", "-10", ";", "policy", "accept", ";", "}"],
                 ["add", "rule", "inet", TABLE, "forward", "ip", "saddr", "@blocked4", "drop"],
                 ["add", "rule", "inet", TABLE, "forward", "ip", "daddr", "@blocked4", "drop"]]
        verb = "add" if action in ("block_device", "suspend_device") else "delete"
        return setup, [[verb, "element", "inet", TABLE, "blocked4", "{", ip, "}"]]

    def apply(self, action, ip):
        setup, cmds = self.plan(action, ip)
        if action != "unblock_device":
            existing = self._run(["list", "chain", "inet", TABLE, "forward"])
            for c in (setup[:3] if existing.returncode != 0 else []) + (setup[3:] if "@blocked4" not in existing.stdout else []):
                r = self._run(c)
                if r.returncode != 0:
                    return False, r.stderr.strip()
        for c in cmds:
            r = self._run(c)
            if r.returncode != 0:
                return False, r.stderr.strip()
        return True, "ok"

    def describe(self, action, ip):
        setup, cmds = self.plan(action, ip)
        return [" ".join(["nft"] + c) for c in (setup + cmds if action != "unblock_device" else cmds)]
