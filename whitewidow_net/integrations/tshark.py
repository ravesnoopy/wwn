"""Captura DNS pasiva con TShark (opcional). Requiere permisos de captura (grupo `wireshark` o capabilities)."""
import shutil
import subprocess
import threading


class TsharkDNS:
    def __init__(self, interface, on_query):
        self.interface, self.on_query = interface, on_query
        self.proc = None

    @staticmethod
    def available():
        return bool(shutil.which("tshark"))

    def start(self):
        if not self.available() or not self.interface:
            return False
        self.proc = subprocess.Popen(
            ["tshark", "-i", self.interface, "-l", "-n", "-Y", "dns.flags.response==0 && dns.qry.name", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        threading.Thread(target=self._read, daemon=True).start()
        return True

    def _read(self):
        for line in self.proc.stdout:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 2 and parts[1]:
                self.on_query(parts[0], parts[1])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
