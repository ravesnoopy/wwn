"""Network Access Control. Solo ejecuta acciones que un adaptador realmente soporta; nada se simula como logrado.
Requiere: control habilitado + confirmación explícita + rol admin. Todo queda en la auditoría."""
import ipaddress
import json
import re
import time

from .integrations.adguard import AdGuardAdapter, DOMAIN_RE
from .integrations.nftables import NftablesAdapter

ALL_ACTIONS = ["block_device", "unblock_device", "suspend_device", "block_domain", "unblock_domain", "limit_bandwidth", "schedule"]
UNSUPPORTED_ALWAYS = {"limit_bandwidth": "Requiere un gateway con QoS (OPNsense/pfSense/tc). No hay adaptador implementado en v1.0.0.",
                      "schedule": "Los horarios requieren un gateway con planificador. No hay adaptador implementado en v1.0.0."}


class ControlError(Exception):
    pass


class Control:
    def __init__(self, db, cfg):
        self.db, self.cfg = db, cfg

    def adapters(self):
        i = self.cfg["integrations"]
        out = []
        if i["nftables"]["enabled"]:
            out.append(NftablesAdapter(i["nftables"]))
        if i["adguard"]["enabled"]:
            out.append(AdGuardAdapter(i["adguard"]))
        return out

    def capabilities(self):
        caps = {"control_enabled": self.cfg["control_enabled"], "dry_run": self.cfg["control_dry_run"], "adapters": {}, "actions": {}}
        for a in self.adapters():
            caps["adapters"][a.name] = a.capabilities()
        for act in ALL_ACTIONS:
            by = [n for n, c in caps["adapters"].items() if c.get("available") and act in c.get("actions", [])]
            caps["actions"][act] = {"supported": bool(by), "adapters": by,
                                    "reason": "" if by else UNSUPPORTED_ALWAYS.get(act, "Ningún adaptador habilitado soporta esta acción.")}
        return caps

    def _adapter_for(self, action):
        for a in self.adapters():
            c = a.capabilities()
            if c.get("available") and action in c.get("actions", []):
                return a
        return None

    def apply(self, action, target, actor, confirm, minutes=None, network_id=None):
        if action not in ALL_ACTIONS:
            raise ControlError("Acción desconocida.")
        if not self.cfg["control_enabled"]:
            self.db.audit(actor, action, target, "rechazado: modo pasivo", ok=False)
            raise ControlError("Control de red deshabilitado (modo pasivo). Actívalo en Ajustes con autorización.")
        if confirm is not True:
            raise ControlError("Se requiere confirmación explícita.")
        if action in ("block_device", "unblock_device", "suspend_device"):
            try:
                ipaddress.IPv4Address(target)
            except ValueError:
                raise ControlError("El objetivo debe ser una IPv4 válida.")
        elif action in ("block_domain", "unblock_domain"):
            target = target.lower().strip(".")
            if not DOMAIN_RE.match(target):
                raise ControlError("Dominio inválido.")
        if action == "suspend_device":
            if not minutes or not (1 <= int(minutes) <= 1440):
                raise ControlError("Indica minutos entre 1 y 1440.")
        adapter = self._adapter_for(action)
        if adapter is None:
            reason = UNSUPPORTED_ALWAYS.get(action) or "Ningún adaptador habilitado y disponible soporta esta acción."
            self.db.audit(actor, action, target, f"no soportado: {reason}", ok=False)
            raise ControlError(reason)
        expires = int(time.time()) + int(minutes) * 60 if action == "suspend_device" else None
        plan = adapter.describe(action, target) if hasattr(adapter, "describe") else adapter.plan(action, target)
        if self.cfg["control_dry_run"]:
            state, detail = "dry_run", "SIMULACIÓN (control_dry_run=true): " + " ; ".join(plan)
        else:
            ok, msg = adapter.apply(action, target)
            state, detail = ("applied" if ok else "failed"), msg
        pid = self.db.execute("INSERT INTO policies(ts,network_id,action,target,params,state,expires_at,adapter,actor,detail) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              (int(time.time()), network_id, action, target, json.dumps({"minutes": minutes}), state, expires, adapter.name, actor, detail))
        if action in ("block_domain", "unblock_domain") and state in ("applied", "dry_run"):
            if action == "block_domain":
                self.db.execute("INSERT OR REPLACE INTO blocklist(domain,ts) VALUES(?,?)", (target, int(time.time())))
            else:
                self.db.execute("DELETE FROM blocklist WHERE domain=?", (target,))
        self.db.audit(actor, action, target, f"{state} via {adapter.name}: {detail}", ok=state != "failed")
        return {"id": pid, "state": state, "adapter": adapter.name, "detail": detail}

    def expire(self):
        """Revierte suspensiones temporales vencidas."""
        now = int(time.time())
        for p in self.db.query("SELECT * FROM policies WHERE action='suspend_device' AND state IN ('applied','dry_run') AND expires_at IS NOT NULL AND expires_at<=?", (now,)):
            if p["state"] == "applied":
                a = self._adapter_for("unblock_device")
                if a:
                    a.apply("unblock_device", p["target"])
            self.db.execute("UPDATE policies SET state='expired' WHERE id=?", (p["id"],))
            self.db.audit("system", "suspension_expired", p["target"], f"policy {p['id']}")
