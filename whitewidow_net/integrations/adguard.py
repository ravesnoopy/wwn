"""Adaptador AdGuard Home (API REST). Bloqueo de dominios y lectura del registro DNS por cliente.
Requiere un AdGuard Home configurado y que los dispositivos usen ese DNS."""
import base64
import json
import re
import urllib.error
import urllib.request

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class AdGuardAdapter:
    name = "adguard"

    def __init__(self, cfg):
        self.c = cfg

    def _req(self, path, data=None, timeout=5):
        url = self.c["url"].rstrip("/") + path
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL de AdGuard inválida")
        req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Content-Type": "application/json"})
        if self.c.get("username"):
            tok = base64.b64encode(f"{self.c['username']}:{self.c.get('password', '')}".encode()).decode()
            req.add_header("Authorization", f"Basic {tok}")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return json.loads(body) if body else {}

    def capabilities(self):
        if not self.c.get("url"):
            return {"available": False, "reason": "AdGuard Home no configurado"}
        try:
            self._req("/control/status")
            return {"available": True, "actions": ["block_domain", "unblock_domain"], "reason": ""}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"available": False, "reason": f"No se pudo conectar: {e}"}

    def _rule(self, d):
        if not DOMAIN_RE.match(d):
            raise ValueError("dominio inválido")
        return f"||{d}^"

    def plan(self, action, domain):
        return [f"AdGuard {'añadir' if action == 'block_domain' else 'quitar'} regla de usuario {self._rule(domain)}"]

    def apply(self, action, domain):
        rule = self._rule(domain)
        try:
            rules = self._req("/control/filtering/status").get("user_rules") or []
            rules = [r for r in rules if r != rule]
            if action == "block_domain":
                rules.append(rule)
            self._req("/control/filtering/set_rules", {"rules": rules})
            return True, "ok"
        except (urllib.error.URLError, OSError, ValueError) as e:
            return False, str(e)

    def query_log(self, limit=200):
        data = self._req("/control/querylog?limit=%d" % limit)
        return [{"client": e.get("client", ""), "domain": (e.get("question") or {}).get("name", "")} for e in data.get("data", [])]
